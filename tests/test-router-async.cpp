#include <gtest/gtest.h>
#include "../http.h" // Provides qb::http::Router, Request, Response, Context, etc.
#include <qb/uuid.h>    // For qb::uuid and qb::generate_random_uuid
#include <memory>
#include <string>
#include <vector>
#include <functional> // For std::function

// --- Helper Classes for Asynchronous Router Tests ---

// Simple Task Executor for testing deferred execution
class TaskExecutor {
public:
    void addTask(std::function<void()> task) {
        _tasks.push_back(std::move(task));
    }

    void processAllTasks() {
        // Process only the tasks currently in the queue when this method is called.
        // This allows tasks to add further tasks to the queue to be processed in a subsequent call.
        std::vector<std::function<void()>> tasks_to_process = _tasks;
        _tasks.clear(); // Clear the main queue before processing so new tasks are added to a fresh queue

        for (auto& task : tasks_to_process) {
            task(); // Execute the task
        }
        // Tasks added by the executed tasks are now in _tasks, to be processed by a subsequent call.
    }

    size_t getPendingTaskCount() const {
        return _tasks.size();
    }

private:
    std::vector<std::function<void()>> _tasks;
};

// Mock Session for Asynchronous Router Tests
struct MockAsyncSession {
    qb::http::Response _response;
    qb::uuid _session_id = qb::generate_random_uuid();
    bool _async_handler_logic_done = false;
    std::string _handler_id_executed;
    qb::http::PathParameters _captured_params;
    std::weak_ptr<qb::http::Context<MockAsyncSession>> _last_context_seen; // For cancellation testing

    qb::http::Response& get_response_ref() { return _response; }

    MockAsyncSession& operator<<(const qb::http::Response& resp) {
        _response = resp;
        return *this;
    }

    [[nodiscard]] const qb::uuid& id() const { return _session_id; }

    void reset() {
        _response = qb::http::Response();
        _async_handler_logic_done = false;
        _handler_id_executed.clear();
        _captured_params = qb::http::PathParameters(); // Correctly re-initialize
    }
};

// Forward declaration for RouterAsyncTest to access _task_executor
class RouterAsyncTest;

// Asynchronous handler implementing ICustomRoute
class TestAsyncHandler : public qb::http::ICustomRoute<MockAsyncSession> {
public:
    TestAsyncHandler(std::string handler_id, TaskExecutor* executor, bool signal_error = false, bool auto_complete_task = true, bool check_cancel_in_task = false)
        : _handler_id(std::move(handler_id)), 
          _executor(executor), 
          _signal_error(signal_error),
          _auto_complete_task(auto_complete_task),
          _check_cancel_in_task(check_cancel_in_task) {}

    // handle is called by the CustomRouteAdapterTask
    void process(std::shared_ptr<qb::http::Context<MockAsyncSession>> ctx) override {
        if (ctx && ctx->session()) {
            ctx->session()->_last_context_seen = ctx; // Store weak_ptr to context
            // Immediately mark that handle was called, before any executor logic
            if (ctx->session()->_handler_id_executed.empty()) {
                 ctx->session()->_handler_id_executed = _handler_id + "_HANDLE_CALLED";
            } else {
                 ctx->session()->_handler_id_executed += ";" + _handler_id + "_HANDLE_CALLED";
            }
        }

        if (!_executor) {
             if (ctx->session()) {
                ctx->session()->_handler_id_executed = _handler_id + "_NO_EXECUTOR";
             }
            ctx->response().status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
            return;
        }

        // Capture ctx to be used in the deferred task
        auto shared_ctx = ctx; 
        _executor->addTask([shared_ctx, handler_id = _handler_id, signal_err = _signal_error, auto_complete = _auto_complete_task, check_cancel = _check_cancel_in_task]() {
            if (check_cancel && shared_ctx->is_cancelled()) {
                if (shared_ctx->session()) {
                    // Ensure the _HANDLE_CALLED suffix is removed if present, then add _CANCELLED_PRE_LOGIC
                    std::string& ids_str = shared_ctx->session()->_handler_id_executed;
                    std::string handle_called_marker = handler_id + "_HANDLE_CALLED";
                    size_t pos = ids_str.rfind(handle_called_marker); // Find last occurrence
                    if (pos != std::string::npos) {
                        // Check if it's a whole token
                        bool start_ok = (pos == 0 || ids_str[pos-1] == ';');
                        bool end_ok = ( (pos + handle_called_marker.length() == ids_str.length()) || 
                                        (pos + handle_called_marker.length() < ids_str.length() && ids_str[pos + handle_called_marker.length()] == ';') );
                        if (start_ok && end_ok) {
                           ids_str.replace(pos, handle_called_marker.length(), handler_id);
                        }
                    }
                    // Now append _CANCELLED_PRE_LOGIC
                    // If handler_id (without _HANDLE_CALLED) is now the last segment or only segment
                    if (ids_str == handler_id || (ids_str.length() > handler_id.length() && ids_str.substr(ids_str.length() - handler_id.length() -1) == (";" + handler_id) )) {
                        ids_str += "_CANCELLED_PRE_LOGIC";
                    } else if (ids_str.empty()) { // Should not be empty if handle was called
                        ids_str = handler_id + "_CANCELLED_PRE_LOGIC";
                    } else { // Append with separator
                        ids_str += ";" + handler_id + "_CANCELLED_PRE_LOGIC";
                    }

                    shared_ctx->session()->_async_handler_logic_done = true; 
                }
                return; 
            }

            if (shared_ctx->session()) {
                std::string& ids_str = shared_ctx->session()->_handler_id_executed;
                std::string handle_called_marker = handler_id + "_HANDLE_CALLED";
                
                size_t pos = ids_str.rfind(handle_called_marker); // Find last occurrence

                if (pos != std::string::npos) {
                    // Check if it's a whole token that we are replacing
                    bool start_ok = (pos == 0 || ids_str[pos-1] == ';');
                    // Ensure replacing this doesn't break a longer ID or sequence incorrectly.
                    // End means either it's the end of the string, or it's followed by a semicolon.
                    bool end_ok = ( (pos + handle_called_marker.length() == ids_str.length()) || 
                                    (pos + handle_called_marker.length() < ids_str.length() && ids_str[pos + handle_called_marker.length()] == ';') );

                    if (start_ok && end_ok) {
                        ids_str.replace(pos, handle_called_marker.length(), handler_id);
                    } else {
                        // Marker found, but not as a clean token (e.g., part of another name).
                        // This case should ideally not happen with distinct handler IDs.
                        // Fallback: if handler_id is not already present as a clean token, append it.
                        std::string current_handler_token = ";" + handler_id;
                        std::string current_handler_token_at_start = handler_id + ";";
                        if (ids_str.find(current_handler_token) == std::string::npos && 
                            ids_str.rfind(current_handler_token_at_start) != 0 && // Check if it's not already at the start
                            ids_str != handler_id) { // Check if it's not the only ID
                           if (!ids_str.empty()) { ids_str += ";"; }
                           ids_str += handler_id;
                        } else if (ids_str.empty()) {
                           ids_str = handler_id;
                        }
                    }
                } else {
                    // _HANDLE_CALLED marker for this handler_id not found.
                    // This implies process() wasn't called, or was already processed, or ID is different.
                    // We should ensure the current handler_id is in the list if its task runs.
                    // Append if not already present as a clean token.
                    std::string current_handler_token = ";" + handler_id;
                    std::string current_handler_token_at_start = handler_id + ";";
                     // Check if handler_id is already present as a complete token
                    bool already_present = (ids_str == handler_id || 
                                           ids_str.find(current_handler_token_at_start) == 0 ||
                                           ids_str.find(current_handler_token) != std::string::npos);
                    if (!already_present) {
                        if (!ids_str.empty()) { ids_str += ";"; }
                        ids_str += handler_id;
                    }
                }
                
                shared_ctx->session()->_captured_params = shared_ctx->path_parameters();
                shared_ctx->session()->_async_handler_logic_done = true;
            }
            
            if (!auto_complete) {
                return; // Task logic done, but don't call complete() from here.
            }
            
            if (signal_err) {
                shared_ctx->response().status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR; // Or any other error code
                shared_ctx->complete(qb::http::AsyncTaskResult::ERROR);
            } else {
                // Default behavior: an async task, once its async operation is done,
                // usually signals completion of this part of the chain.
                // If it were part of a longer chain needing more async steps, it might be CONTINUE.
                // For a final handler, COMPLETE is typical.
                shared_ctx->response().status_code = HTTP_STATUS_OK;
                shared_ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
            }
        });
        // IMPORTANT: The TestAsyncHandler::handle method itself does NOT call ctx->complete() here.
        // The CustomRouteAdapterTask, which wraps this ICustomRoute, expects the ICustomRoute::handle
        // method to eventually lead to ctx->complete(). In this async scenario, the completion
        // is deferred and will be called by the task scheduled on the _executor.
        // The CustomRouteAdapterTask will simply return after this handle method returns,
        // and the Context will wait for someone (the deferred task) to call ctx->complete().
    }

    std::string name() const override {
        return _handler_id;
    }
    
    void cancel() override {
        // Optional: Implement cancellation logic if the async task can be cancelled
        // For example, mark a flag that the deferred task checks.
    }

    TaskExecutor* getExecutorUsed() const { return _executor; }

private:
    std::string _handler_id;
    TaskExecutor* _executor;
    bool _signal_error;
    bool _auto_complete_task;
    bool _check_cancel_in_task;
};

// Asynchronous Middleware implementing IMiddleware
class TestAsyncMiddleware : public qb::http::IMiddleware<MockAsyncSession> {
public:
    TestAsyncMiddleware(std::string id, TaskExecutor* executor, 
                        std::string header_name = "X-Async-Middleware", 
                        std::string header_value = "Applied", 
                        bool signal_error_in_task = false,
                        bool check_cancel_in_task = false)
        : _id(std::move(id)), 
          _executor(executor), 
          _header_name(std::move(header_name)), 
          _header_value(std::move(header_value)),
          _signal_error_in_task(signal_error_in_task),
          _check_cancel_in_task(check_cancel_in_task) {}

    void process(std::shared_ptr<qb::http::Context<MockAsyncSession>> ctx) override {
        if (ctx && ctx->session()) {
            ctx->session()->_last_context_seen = ctx; // Store weak_ptr for potential cancellation triggering
        }
        if (!_executor) {
            ctx->response().set_header(_id + "-Error", "NoExecutor");
            ctx->complete(qb::http::AsyncTaskResult::ERROR); 
            return;
        }

        auto shared_ctx = ctx;
        _executor->addTask([shared_ctx, hid = _id, hn = _header_name, hv = _header_value, 
                            signal_err_task = _signal_error_in_task, check_cancel_task = _check_cancel_in_task]() {
            // Check for cancellation first if configured
            if (check_cancel_task && shared_ctx->is_cancelled()) {
                if (shared_ctx->session()) { 
                    if (shared_ctx->session()->_handler_id_executed.empty()) {
                        shared_ctx->session()->_handler_id_executed = hid + "_TASK_CANCELLED";
                    } else {
                        shared_ctx->session()->_handler_id_executed += ";" + hid + "_TASK_CANCELLED";
                    }
                }
                // If task is cancelled, it might not call complete(), or call complete(CANCELLED).
                // For this test helper, we assume the external cancel call on context handles finalization.
                // The task itself just aborts its normal operation.
                return; 
            }

            if (signal_err_task) {
                if (shared_ctx->session()) { 
                    if (shared_ctx->session()->_handler_id_executed.empty()) {
                        shared_ctx->session()->_handler_id_executed = hid + "_ERROR_SIGNALLED";
                    } else {
                        shared_ctx->session()->_handler_id_executed += ";" + hid + "_ERROR_SIGNALLED";
                    }
                }
                shared_ctx->response().status_code = HTTP_STATUS_SERVICE_UNAVAILABLE; 
                shared_ctx->complete(qb::http::AsyncTaskResult::ERROR);
                return;
            }
            
            shared_ctx->response().set_header(hn, hv);
            if (shared_ctx->session()) { 
                 if (shared_ctx->session()->_handler_id_executed.empty()) {
                    shared_ctx->session()->_handler_id_executed = hid;
                 } else {
                    shared_ctx->session()->_handler_id_executed += ";" + hid;
                 }
            }
            shared_ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
        });
    }

    std::string name() const override { return _id; }
    void cancel() override { 
        // This cancel is for the IAsyncTask interface. 
        // Actual cancellation for test purposes is handled by the lambda checking ctx->is_cancelled().
    }

private:
    std::string _id;
    TaskExecutor* _executor;
    std::string _header_name;
    std::string _header_value;
    bool _signal_error_in_task;
    bool _check_cancel_in_task;
};

// Test Fixture for Asynchronous Router Tests
class RouterAsyncTest : public ::testing::Test {
protected:
    std::shared_ptr<MockAsyncSession> mock_session;
    qb::http::Router<MockAsyncSession> router;
    TaskExecutor _task_executor; // Test-specific task executor

    void SetUp() override {
        mock_session = std::make_shared<MockAsyncSession>();
        // Router is default-constructed, will use the standard _on_finalized_callback
        // that updates the session.
    }

    ~RouterAsyncTest() noexcept override = default;

    qb::http::Request create_request(qb::http::method method_val, const std::string& target_path) {
        qb::http::Request req;
        req.method = method_val;
        try {
            req.uri() = qb::io::uri(target_path);
        } catch (const std::exception& e) {
            ADD_FAILURE() << "Failed to parse URI: " << target_path << " - " << e.what();
            req.uri() = qb::io::uri("/__invalid_uri_due_to_parse_failure__");
        }
        req.major_version = 1;
        req.minor_version = 1;
        return req;
    }
};

// --- Basic Asynchronous Route Tests (with deferred execution model) ---

TEST_F(RouterAsyncTest, SimpleAsyncGetRouteDeferred) {
    // Pass the test fixture's _task_executor to the handler
    auto asyncHandler = std::make_shared<TestAsyncHandler>("async_hello_handler", &_task_executor);
    
    // Register the ICustomRoute-based handler
    router.get("/async/hello", asyncHandler); 

    router.compile();

    auto request = create_request(HTTP_GET, "/async/hello");
    
    // TestAsyncHandler::handle will then enqueue its logic onto _task_executor.
    router.route(mock_session, std::move(request)); 

    // Verify task was deferred by TestAsyncHandler::handle
    ASSERT_FALSE(mock_session->_async_handler_logic_done) << "Async handler logic ran prematurely.";
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Task was not enqueued by the TestAsyncHandler.";
    
    _task_executor.processAllTasks(); // Manually process the queued task

    // Verify task completion and effects
    ASSERT_TRUE(mock_session->_async_handler_logic_done) << "Async handler logic did not complete.";
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(mock_session->_handler_id_executed, "async_hello_handler");
}

TEST_F(RouterAsyncTest, AsyncRouteWithPathParametersDeferred) {
    auto asyncHandler = std::make_shared<TestAsyncHandler>("async_params_handler", &_task_executor);
    ASSERT_NE(asyncHandler, nullptr);
    ASSERT_NE(asyncHandler->getExecutorUsed(), nullptr) << "TestAsyncHandler has a null executor pointer after construction.";
    ASSERT_EQ(asyncHandler->getExecutorUsed(), &_task_executor) << "TestAsyncHandler is not using the fixture's TaskExecutor instance!";
    
    router.get("/async/params/:id", asyncHandler);
    router.compile();

    auto request = create_request(HTTP_GET, "/async/params/123");
    router.route(mock_session, std::move(request));

    // Check if TestAsyncHandler::handle was even called by looking for the immediate side-effect.
    EXPECT_EQ(mock_session->_handler_id_executed, "async_params_handler_HANDLE_CALLED") 
        << "TestAsyncHandler::handle was not called or did not set _handler_id_executed as expected.";

    ASSERT_FALSE(mock_session->_async_handler_logic_done);
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) 
        << "Task was not enqueued by TestAsyncHandler into the fixture's TaskExecutor, despite TestAsyncHandler::handle apparently being called.";
    _task_executor.processAllTasks();

    ASSERT_TRUE(mock_session->_async_handler_logic_done);
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(mock_session->_handler_id_executed, "async_params_handler") 
        << "The async task did not run or did not update _handler_id_executed to the final value.";
    EXPECT_EQ(mock_session->_captured_params.get("id").value_or(""), "123");
}

TEST_F(RouterAsyncTest, AsyncRouteWithSyncMiddlewareDeferred) {
    router.use([](auto ctx, auto next) {
        ctx->response().set_header("X-Sync-Middleware", "Applied");
        if (ctx->session()) { // It's good practice to check for session existence
             if (ctx->session()->_handler_id_executed.empty()) {
                ctx->session()->_handler_id_executed = "sync_mw";
             } else {
                ctx->session()->_handler_id_executed += ";sync_mw";
             }
        }
        next(); 
    });

    auto asyncHandler = std::make_shared<TestAsyncHandler>("async_after_sync_mw", &_task_executor);
    router.get("/async/with_sync_mw", asyncHandler);
    router.compile();

    auto request = create_request(HTTP_GET, "/async/with_sync_mw");
    router.route(mock_session, std::move(request));

    ASSERT_FALSE(mock_session->_async_handler_logic_done);
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1);
    
    // _handler_id_executed is updated directly on the session by sync middleware, 
    // and then TestAsyncHandler::handle is called by the task system before control returns here.
    EXPECT_EQ(mock_session->_handler_id_executed, "sync_mw;async_after_sync_mw_HANDLE_CALLED") 
        << "Sync middleware ran, and TestAsyncHandler::handle should have been called appending its HANDLE_CALLED marker.";
    
    _task_executor.processAllTasks(); // Async handler runs, calls ctx->complete(COMPLETE), then context finalizes

    // Header check should be valid now as context is finalized.
    EXPECT_EQ(mock_session->_response.header("X-Sync-Middleware"), "Applied") 
        << "Header from sync middleware not found after task completion.";
    ASSERT_TRUE(mock_session->_async_handler_logic_done);
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(mock_session->_handler_id_executed, "sync_mw;async_after_sync_mw");
}

TEST_F(RouterAsyncTest, MultipleAsyncRoutesDeferred) {
    auto asyncHandler1 = std::make_shared<TestAsyncHandler>("async_route1", &_task_executor);
    auto asyncHandler2 = std::make_shared<TestAsyncHandler>("async_route2", &_task_executor);

    router.get("/async/path1", asyncHandler1);
    router.get("/async/path2", asyncHandler2);
    router.compile();

    // Test path1
    auto request1 = create_request(HTTP_GET, "/async/path1");
    router.route(mock_session, std::move(request1));
    ASSERT_FALSE(mock_session->_async_handler_logic_done);
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1);
    _task_executor.processAllTasks();
    ASSERT_TRUE(mock_session->_async_handler_logic_done);
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(mock_session->_handler_id_executed, "async_route1");

    // Reset for next request
    mock_session->reset();
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 0);

    // Test path2
    auto request2 = create_request(HTTP_GET, "/async/path2");
    router.route(mock_session, std::move(request2));
    ASSERT_FALSE(mock_session->_async_handler_logic_done);
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1);
    _task_executor.processAllTasks();
    ASSERT_TRUE(mock_session->_async_handler_logic_done);
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(mock_session->_handler_id_executed, "async_route2");
}

TEST_F(RouterAsyncTest, AsyncMiddlewareAndAsyncHandler) {
    auto asyncMiddleware = std::make_shared<TestAsyncMiddleware>("async_mw", &_task_executor);
    auto asyncHandler = std::make_shared<TestAsyncHandler>("async_handler_after_async_mw", &_task_executor);

    router.use(asyncMiddleware);
    router.get("/async/mw_then_handler", asyncHandler);
    router.compile();

    auto request = create_request(HTTP_GET, "/async/mw_then_handler");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Middleware task was not enqueued.";
    ASSERT_FALSE(mock_session->_async_handler_logic_done);
    EXPECT_TRUE(mock_session->_handler_id_executed.empty()) << "handler_id_executed should be empty before middleware task runs.";

    _task_executor.processAllTasks(); // Async Middleware task runs, calls complete(CONTINUE). Handler's process() is called and queues its task.

    // After middleware's task, its effects (ID) should be visible. Handler's task should now be in the queue.
    // TestAsyncHandler::handle should have been called.
    // Header is NOT YET in mock_session->_response, as context is not finalized.
    EXPECT_EQ(mock_session->_handler_id_executed, "async_mw;async_handler_after_async_mw_HANDLE_CALLED") 
        << "Async middleware ID and handler's HANDLE_CALLED marker expected.";
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Handler task was not enqueued after middleware task completion.";
    ASSERT_FALSE(mock_session->_async_handler_logic_done); 

    _task_executor.processAllTasks(); // Async Handler's task runs, calls complete(COMPLETE). Context finalizes.

    // Now context is finalized, header from async middleware should be in session.
    EXPECT_EQ(mock_session->_response.header("X-Async-Middleware"), "Applied") 
        << "Header from async middleware not found after its task completion.";
    ASSERT_TRUE(mock_session->_async_handler_logic_done);
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(mock_session->_handler_id_executed, "async_mw;async_handler_after_async_mw");
}

TEST_F(RouterAsyncTest, AsyncHandlerSignalsError) {
    // Configure TestAsyncHandler to signal an error and not auto-complete (it will complete with ERROR)
    auto asyncHandler = std::make_shared<TestAsyncHandler>("async_error_handler", &_task_executor, true /* signal_error */);
    router.get("/async/error", asyncHandler);
    router.compile();

    auto request = create_request(HTTP_GET, "/async/error");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1);
    _task_executor.processAllTasks();

    ASSERT_TRUE(mock_session->_async_handler_logic_done);
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(mock_session->_handler_id_executed, "async_error_handler");
}

TEST_F(RouterAsyncTest, MixedTaskChain_SyncMw_AsyncMw_AsyncHandler) {
    // 1. Sync Middleware (functional)
    router.use([](auto ctx, auto next) {
        ctx->response().set_header("X-Sync-Test", "SyncApplied");
        if (ctx->session()) { 
            ctx->session()->_handler_id_executed += (ctx->session()->_handler_id_executed.empty() ? "" : ";") + std::string("sync_functional_mw");
        }
        next();
    });

    // 2. Async Middleware (TestAsyncMiddleware)
    auto asyncMiddleware = std::make_shared<TestAsyncMiddleware>("async_test_mw", &_task_executor, "X-Async-Test", "AsyncApplied");
    router.use(asyncMiddleware);

    // 3. Async Handler (TestAsyncHandler)
    auto asyncHandler = std::make_shared<TestAsyncHandler>("async_final_handler", &_task_executor);
    router.get("/async/mixed_chain", asyncHandler);

    router.compile();

    auto request = create_request(HTTP_GET, "/async/mixed_chain");
    router.route(mock_session, std::move(request));

    // After router.route():
    // - Sync middleware runs immediately: _handler_id_executed = "sync_functional_mw"
    // - Async middleware's (TestAsyncMiddleware) IAsyncTask::execute() calls its process() method.
    // - TestAsyncMiddleware::process() enqueues its lambda onto _task_executor.
    // - TestAsyncHandler::process() has NOT YET been called.
    EXPECT_EQ(mock_session->_handler_id_executed, "sync_functional_mw") 
        << "After route(): Only sync_functional_mw ID expected.";
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Async middleware's (TestAsyncMiddleware) lambda task not queued.";
    ASSERT_FALSE(mock_session->_async_handler_logic_done); 

    _task_executor.processAllTasks(); // Process TestAsyncMiddleware's lambda task.
    
    // TestAsyncMiddleware's lambda task has run:
    //    - Sets "X-Async-Test" header on ctx->response().
    //    - Updates session: _handler_id_executed = "sync_functional_mw;async_test_mw".
    //    - Calls ctx->complete(CONTINUE).
    // RouterCore immediately processes the next task in the chain: CustomRouteAdapterTask for TestAsyncHandler.
    // CustomRouteAdapterTask::execute() calls TestAsyncHandler::process().
    // TestAsyncHandler::process() then:
    //    - Updates session: _handler_id_executed = "sync_functional_mw;async_test_mw;async_final_handler_HANDLE_CALLED".
    //    - Enqueues TestAsyncHandler's lambda onto _task_executor.
    // Headers are NOT YET in mock_session->_response, only on ctx->response().
    EXPECT_EQ(mock_session->_handler_id_executed, "sync_functional_mw;async_test_mw;async_final_handler_HANDLE_CALLED")
         << "After TestAsyncMiddleware task & TestAsyncHandler::process(): sync_mw_id;async_mw_id;handler_HANDLE_CALLED expected.";
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "TestAsyncHandler's lambda task not queued.";
    ASSERT_FALSE(mock_session->_async_handler_logic_done); // TestAsyncHandler's core logic (its lambda) not yet run.

    _task_executor.processAllTasks(); // Process TestAsyncHandler's lambda task. This calls complete(COMPLETE). Context finalizes.

    // TestAsyncHandler's lambda task has run:
    //    - Updates session: _handler_id_executed = "sync_functional_mw;async_test_mw;async_final_handler".
    //    - Sets _async_handler_logic_done = true.
    //    - Calls ctx->complete(COMPLETE).
    // Context is now finalized. _on_request_finalized_callback runs, copying ctx->response() to mock_session->_response.
    // All headers ("X-Sync-Test", "X-Async-Test") should now be in mock_session->_response.
    EXPECT_EQ(mock_session->_response.header("X-Sync-Test"), "SyncApplied") << "X-Sync-Test header missing after all tasks."; 
    EXPECT_EQ(mock_session->_response.header("X-Async-Test"), "AsyncApplied") << "X-Async-Test header missing or incorrect after all tasks."; // Corrected expected value
    ASSERT_TRUE(mock_session->_async_handler_logic_done);
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(mock_session->_handler_id_executed, "sync_functional_mw;async_test_mw;async_final_handler");
}

TEST_F(RouterAsyncTest, AsyncHandlerCancellation) {
    // TestAsyncHandler configured to not auto-complete its task and to check for cancellation
    auto asyncHandler = std::make_shared<TestAsyncHandler>("async_cancel_handler", &_task_executor, false /*signal_error*/, false /*auto_complete_task*/, true /*check_cancel_in_task*/);
    router.get("/async/cancel", asyncHandler);
    router.compile();

    auto request = create_request(HTTP_GET, "/async/cancel");
    router.route(mock_session, std::move(request)); // This calls TestAsyncHandler::handle, which queues a task

    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Task was not enqueued by TestAsyncHandler.";
    ASSERT_FALSE(mock_session->_async_handler_logic_done) << "Async handler logic ran prematurely.";
    
    // Get the context to cancel it. TestAsyncHandler should have stored it.
    std::shared_ptr<qb::http::Context<MockAsyncSession>> ctx_to_cancel;
    ASSERT_FALSE(mock_session->_last_context_seen.expired()) << "Context was not captured by TestAsyncHandler.";
    ctx_to_cancel = mock_session->_last_context_seen.lock();
    ASSERT_TRUE(ctx_to_cancel) << "Could not get context for cancellation.";

    // Cancel the context. This should set response to 500 if it was 200.
    ctx_to_cancel->cancel("Test initiated cancellation");
    
    // At this point, context is cancelled. Its internal response should be 500.
    // The _on_finalized_callback (which copies to session) has run because cancel() calls complete(CANCELLED).
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE) 
        << "Session response status should be 503 immediately after context cancellation and its finalization.";

    // Now, process the task that TestAsyncHandler had queued.
    // The task logic in TestAsyncHandler (configured with check_cancel_in_task=true) 
    // should see that the context is_cancelled() and not perform its normal operation.
    // It should mark _async_handler_logic_done = true and update _handler_id_executed.
    _task_executor.processAllTasks();

    EXPECT_TRUE(ctx_to_cancel->is_cancelled());
    EXPECT_TRUE(ctx_to_cancel->is_completed());
    // Check session again, it should still be 500. The handler task should not change it.
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);
    ASSERT_TRUE(mock_session->_async_handler_logic_done);
    // Ensure the handler's async logic was marked as "cancelled pre logic"
    EXPECT_EQ(mock_session->_handler_id_executed, "async_cancel_handler_CANCELLED_PRE_LOGIC");
}

// --- New Cancellation Tests ---

TEST_F(RouterAsyncTest, CancelBeforeAnyTasksProcessed) {
    auto asyncHandler = std::make_shared<TestAsyncHandler>("async_cancel_immediate", &_task_executor, false, true, true);
    router.get("/async/cancel_early", asyncHandler);
    router.compile();

    auto request = create_request(HTTP_GET, "/async/cancel_early");
    router.route(mock_session, std::move(request));

    // Handler's process() method has run and queued a task.
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Task was not enqueued by the TestAsyncHandler.";
    ASSERT_FALSE(mock_session->_async_handler_logic_done) << "Async handler logic ran prematurely.";

    // Cancel the context before processing any tasks from the executor
    std::shared_ptr<qb::http::Context<MockAsyncSession>> ctx_to_cancel;
    if (!mock_session->_last_context_seen.expired()) {
        ctx_to_cancel = mock_session->_last_context_seen.lock();
    }
    ASSERT_TRUE(ctx_to_cancel) << "Could not get context for cancellation.";
    
    ctx_to_cancel->cancel("Cancelled before executor processing");

    // Now, try to process tasks. The handler's task should see it's cancelled.
    _task_executor.processAllTasks();

    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);
    ASSERT_TRUE(mock_session->_async_handler_logic_done); // Marked done by TestAsyncHandler when it sees cancellation
    EXPECT_EQ(mock_session->_handler_id_executed, "async_cancel_immediate_CANCELLED_PRE_LOGIC");
    EXPECT_TRUE(ctx_to_cancel->is_cancelled());
    EXPECT_TRUE(ctx_to_cancel->is_completed());
}

TEST_F(RouterAsyncTest, CancelDuringAsyncMiddlewareBeforeHandlerTask) {
    auto asyncMiddleware = std::make_shared<TestAsyncMiddleware>("async_mw_cancel", &_task_executor);
    auto asyncHandler = std::make_shared<TestAsyncHandler>("async_handler_after_mw_cancel", &_task_executor, false, true, true);

    router.use(asyncMiddleware);
    router.get("/async/mw_then_cancel/:id", asyncHandler); 
    router.compile();

    auto request = create_request(HTTP_GET, "/async/mw_then_cancel/1");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Middleware task was not enqueued.";
    EXPECT_TRUE(mock_session->_handler_id_executed.empty()) << "No IDs should be set before middleware task runs.";
    
    _task_executor.processAllTasks(); // Async Middleware task runs, calls complete(CONTINUE). Handler's process() is called & queues its task.

    // After middleware task: its ID recorded. Handler's process() called, adds _HANDLE_CALLED, queues task.
    // Header from TestAsyncMiddleware is on ctx->response, BUT NOT YET in mock_session.
    EXPECT_EQ(mock_session->_handler_id_executed, "async_mw_cancel;async_handler_after_mw_cancel_HANDLE_CALLED");
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Handler task was not enqueued after middleware.";
    ASSERT_FALSE(mock_session->_async_handler_logic_done); 

    std::shared_ptr<qb::http::Context<MockAsyncSession>> ctx_to_cancel;
    if (!mock_session->_last_context_seen.expired()) {
        ctx_to_cancel = mock_session->_last_context_seen.lock();
    }
    ASSERT_TRUE(ctx_to_cancel) << "Could not get context for cancellation.";
    
    ctx_to_cancel->cancel("Cancelled after middleware, before handler task execution");
    // cancel() calls complete(CANCELLED), which finalizes and updates session.
    // NOW the header from middleware should be in the session.
    EXPECT_EQ(mock_session->_response.header("X-Async-Middleware"), "Applied");
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);

    _task_executor.processAllTasks(); // Process handler's task, it should see cancellation.

    ASSERT_TRUE(mock_session->_async_handler_logic_done); 
    EXPECT_EQ(mock_session->_handler_id_executed, "async_mw_cancel;async_handler_after_mw_cancel_CANCELLED_PRE_LOGIC");
    EXPECT_TRUE(ctx_to_cancel->is_cancelled());
    EXPECT_TRUE(ctx_to_cancel->is_completed());
}

TEST_F(RouterAsyncTest, CancelContextAlreadyOnErrorStatus) {
    // Create a dummy request and response prototype for context construction
    qb::http::Request req;
    req.method = HTTP_GET;
    req.uri() = qb::io::uri("/test");
    qb::http::Response resp_proto;

    // Create a context directly.
    // The on_finalized_callback would normally be set by RouterCore. 
    // For this test, we don't strictly need it to be the router's one if we only check context state.
    // However, to check session state, we do need a callback that updates the session.
    auto temp_session = std::make_shared<MockAsyncSession>();
    
    std::function<void(qb::http::Context<MockAsyncSession>&)> on_finalized_for_test = 
        [&temp_session](qb::http::Context<MockAsyncSession>& fin_ctx) {
        if (temp_session) {
            *temp_session << fin_ctx.response(); // Copy response to session
        }
    };

    auto ctx = std::make_shared<qb::http::Context<MockAsyncSession>>(
        std::move(req), 
        std::move(resp_proto), 
        temp_session, 
        on_finalized_for_test,
        router.get_core_weak_ptr()
    );

    // Set an initial error status
    ctx->response().status_code = HTTP_STATUS_NOT_FOUND; // e.g., 404
    temp_session->get_response_ref().status_code = HTTP_STATUS_NOT_FOUND; // Simulate it being in session too

    // Cancel the context
    ctx->cancel("Testing cancellation on 404");

    // The finalize_processing (called by complete(CANCELLED) inside cancel()) should run the callback.
    
    // Status code in the context should be overridden to 503 by cancel logic
    EXPECT_EQ(ctx->response().status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);
    // And this should be reflected in the session after finalization
    EXPECT_EQ(temp_session->_response.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);

    EXPECT_TRUE(ctx->is_cancelled());
    EXPECT_TRUE(ctx->is_completed()); // cancel() calls complete(), which calls finalize_processing()
}

// --- New Test Cases (Batch 1) ---

TEST_F(RouterAsyncTest, AsyncPostRouteDeferred) {
    auto asyncHandler = std::make_shared<TestAsyncHandler>("async_post_handler", &_task_executor);
    router.post("/async/post_data", asyncHandler); 
    router.compile();

    auto request = create_request(HTTP_POST, "/async/post_data");
    // Optionally add a request body for POST, though TestAsyncHandler doesn't use it yet
    // request.body() = "sample_post_body"; 
    // request.set_header("Content-Type", "text/plain");

    router.route(mock_session, std::move(request)); 

    EXPECT_EQ(mock_session->_handler_id_executed, "async_post_handler_HANDLE_CALLED");
    ASSERT_FALSE(mock_session->_async_handler_logic_done);
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1);
    
    _task_executor.processAllTasks();

    ASSERT_TRUE(mock_session->_async_handler_logic_done);
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(mock_session->_handler_id_executed, "async_post_handler");
}

TEST_F(RouterAsyncTest, AsyncPutRouteDeferred) {
    auto asyncHandler = std::make_shared<TestAsyncHandler>("async_put_handler", &_task_executor);
    router.put("/async/put_data", asyncHandler);
    router.compile();

    auto request = create_request(HTTP_PUT, "/async/put_data");
    router.route(mock_session, std::move(request)); 

    EXPECT_EQ(mock_session->_handler_id_executed, "async_put_handler_HANDLE_CALLED");
    ASSERT_FALSE(mock_session->_async_handler_logic_done);
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1);
    
    _task_executor.processAllTasks();

    ASSERT_TRUE(mock_session->_async_handler_logic_done);
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(mock_session->_handler_id_executed, "async_put_handler");
}

TEST_F(RouterAsyncTest, AsyncMiddlewareTaskSignalsError) {
    // Configure TestAsyncMiddleware to signal an error from its task
    auto erroringMiddleware = std::make_shared<TestAsyncMiddleware>("error_mw", &_task_executor, 
                                                                  "X-Error-Middleware", "ErrorSignalled", 
                                                                  true /* signal_error_in_task */);
    // Add a normal async handler that should NOT be reached if middleware errors out
    auto asyncHandler = std::make_shared<TestAsyncHandler>("handler_after_error_mw", &_task_executor);

    router.use(erroringMiddleware);
    router.get("/async/mw_signals_error", asyncHandler);
    router.compile();

    auto request = create_request(HTTP_GET, "/async/mw_signals_error");
    router.route(mock_session, std::move(request));

    // erroringMiddleware::handle is called, queues its task.
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Erroring middleware task not queued.";
    EXPECT_TRUE(mock_session->_handler_id_executed.empty()) << "No ID should be set before task execution.";

    _task_executor.processAllTasks(); // Process the erroring middleware's task.
                                      // This task should call ctx->complete(ERROR).

    // Verify middleware signalled error and context finalized with error
    EXPECT_EQ(mock_session->_handler_id_executed, "error_mw_ERROR_SIGNALLED");
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR) 
        << "Context should have error status from middleware.";
    
    // The next handler (asyncHandler) should not have been processed or its task queued.
    ASSERT_FALSE(mock_session->_async_handler_logic_done) << "Downstream handler logic ran despite middleware error.";
    // Task queue should be empty as the chain was aborted by erroring middleware.
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 0) << "No further tasks should be queued after middleware error.";
}

// --- New Test Cases (Batch 2) ---

TEST_F(RouterAsyncTest, RouteGroupWithAsyncMiddlewareAndHandler) {
    auto groupAsyncMiddleware = std::make_shared<TestAsyncMiddleware>("group_async_mw", &_task_executor, "X-Group-Async-MW");
    auto routeAsyncHandler = std::make_shared<TestAsyncHandler>("group_route_async_handler", &_task_executor);

    auto group = router.group("/api/group");
    group->use(groupAsyncMiddleware);
    group->get("/resource", routeAsyncHandler);

    router.compile();

    auto request = create_request(HTTP_GET, "/api/group/resource");
    router.route(mock_session, std::move(request));

    // Group's async middleware process() is called, queues its task.
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Group middleware task not queued.";
    EXPECT_TRUE(mock_session->_handler_id_executed.empty()) << "Handler ID string should be empty initially.";

    _task_executor.processAllTasks(); // Process group middleware's task.
                                      // This task calls complete(CONTINUE), leading to handler's process() being called.

    // Group middleware ran, its ID recorded. Handler's process() was called, appended _HANDLE_CALLED & queued its task.
    EXPECT_EQ(mock_session->_handler_id_executed, "group_async_mw;group_route_async_handler_HANDLE_CALLED");
    // Header from group middleware is on ctx->response, not yet on mock_session.
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Route handler task not queued.";
    ASSERT_FALSE(mock_session->_async_handler_logic_done);

    _task_executor.processAllTasks(); // Process route handler's task.
                                      // This task calls complete(COMPLETE), context finalizes.

    ASSERT_TRUE(mock_session->_async_handler_logic_done);
    EXPECT_EQ(mock_session->_response.header("X-Group-Async-MW"), "Applied");
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(mock_session->_handler_id_executed, "group_async_mw;group_route_async_handler");
}

TEST_F(RouterAsyncTest, AsyncMiddlewareTaskCancellation) {
    // Configure TestAsyncMiddleware to check for cancellation in its task
    auto cancellableMiddleware = std::make_shared<TestAsyncMiddleware>("cancel_check_mw", &_task_executor, 
                                                                       "X-Cancel-Check-MW", "NotAppliedDueToCancel",
                                                                       false /* signal_error_in_task */,
                                                                       true  /* check_cancel_in_task */);
    auto asyncHandler = std::make_shared<TestAsyncHandler>("handler_after_cancel_check_mw", &_task_executor);

    router.use(cancellableMiddleware);
    router.get("/async/mw_task_cancel", asyncHandler);
    router.compile();

    auto request = create_request(HTTP_GET, "/async/mw_task_cancel");
    router.route(mock_session, std::move(request));

    // cancellableMiddleware::handle is called, queues its task and stores context.
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Cancellable middleware task not queued.";
    EXPECT_TRUE(mock_session->_handler_id_executed.empty());

    // Get the context to cancel it (TestAsyncMiddleware now stores _last_context_seen).
    std::shared_ptr<qb::http::Context<MockAsyncSession>> ctx_to_cancel;
    ASSERT_FALSE(mock_session->_last_context_seen.expired()) << "Context was not captured by TestAsyncMiddleware.";
    ctx_to_cancel = mock_session->_last_context_seen.lock();
    ASSERT_TRUE(ctx_to_cancel) << "Could not get context for cancellation.";

    ctx_to_cancel->cancel("Test initiated cancellation of middleware task");
    // cancel() calls complete(CANCELLED), which finalizes and updates session.
    // The middleware's specific header ("X-Cancel-Check-MW") should NOT be set by its task later.
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);

    _task_executor.processAllTasks(); // Process the cancellable middleware's task.
                                      // Its task lambda should see is_cancelled() and exit early.

    EXPECT_EQ(mock_session->_handler_id_executed, "cancel_check_mw_TASK_CANCELLED");
    EXPECT_EQ(mock_session->_response.header("X-Cancel-Check-MW"), "") 
        << "Header should not be set if middleware task was cancelled before setting it.";
    
    ASSERT_FALSE(mock_session->_async_handler_logic_done) << "Downstream handler logic ran despite middleware task cancellation.";
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 0) << "No further tasks should be queued if middleware task cancelled.";
}

// --- New Test Cases (Batch 3) ---

TEST_F(RouterAsyncTest, NotFoundWithGlobalAsyncMiddleware) {
    // Configure TestAsyncMiddleware to NOT signal an error and to check for cancellation (though not strictly needed here)
    auto globalAsyncMiddleware = std::make_shared<TestAsyncMiddleware>("global_async_mw", &_task_executor, 
                                                                     "X-Global-Async-MW", "AppliedGlobal", 
                                                                     false /* signal_error_in_task */,
                                                                     false /* check_cancel_in_task */);
    router.use(globalAsyncMiddleware); // Global middleware
    
    // Add a known route to make sure the router is not empty, but we will request a different one.
    auto asyncHandler = std::make_shared<TestAsyncHandler>("some_other_handler", &_task_executor);
    router.get("/some/known/path", asyncHandler);

    router.compile();

    auto request = create_request(HTTP_GET, "/this/path/does/not/exist");
    router.route(mock_session, std::move(request));

    // Global middleware's process() should have been called and its task queued,
    // as it's part of the chain for any request, even if it leads to a 404.
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Global middleware task not queued for non-matching route.";
    EXPECT_TRUE(mock_session->_handler_id_executed.empty());

    _task_executor.processAllTasks(); // Process the global middleware's task.
                                      // It should call ctx->complete(CONTINUE).
                                      // RouterCore should then find no matching route and set 404.
                                      // The context will then be finalized.

    // Global middleware's task should have run and set its ID and header.
    EXPECT_EQ(mock_session->_handler_id_executed, "global_async_mw");
    EXPECT_EQ(mock_session->_response.header("X-Global-Async-MW"), "AppliedGlobal");
    
    // Final status should be 404 Not Found.
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND);
    
    // The other handler should not have been involved.
    ASSERT_FALSE(mock_session->_async_handler_logic_done);
}

TEST_F(RouterAsyncTest, AsyncLambdaHandlerDeferred) {
    router.get("/async/lambda", [this](std::shared_ptr<qb::http::Context<MockAsyncSession>> ctx) {
        if (ctx && ctx->session()) { 
            ctx->session()->_handler_id_executed = "lambda_HANDLE_CALLED";
            // Store context for cancellation tests if needed, though not primary for this test
            ctx->session()->_last_context_seen = ctx; 
        }
        _task_executor.addTask([ctx, this]() { // Capture this for _task_executor if it's a member, or pass explicitly
            if (ctx && ctx->session()) {
                // Replace _HANDLE_CALLED with final ID
                std::string& ids_str = ctx->session()->_handler_id_executed;
                std::string marker = "lambda_HANDLE_CALLED";
                if (ids_str == marker) { // Simple replacement if it's the only one
                    ids_str = "lambda_executed";
                } else { // Fallback or more complex logic if needed
                    ids_str = "lambda_executed"; 
                }
                ctx->session()->_async_handler_logic_done = true;
            }
            if (ctx) { // Always check ctx before using
                ctx->response().status_code = HTTP_STATUS_OK;
                ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
            }
        });
    });

    router.compile();

    auto request = create_request(HTTP_GET, "/async/lambda");
    router.route(mock_session, std::move(request));

    // Lambda handler (outer part) runs, queues task, sets _HANDLE_CALLED.
    EXPECT_EQ(mock_session->_handler_id_executed, "lambda_HANDLE_CALLED");
    ASSERT_FALSE(mock_session->_async_handler_logic_done);
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Task not enqueued by async lambda.";

    _task_executor.processAllTasks(); // Process the lambda's deferred task.

    ASSERT_TRUE(mock_session->_async_handler_logic_done);
    EXPECT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(mock_session->_handler_id_executed, "lambda_executed");
} 
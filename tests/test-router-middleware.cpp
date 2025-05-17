#include <gtest/gtest.h>
#include "../http.h" // Provides qb::http::Router, Request, Response, Context, etc.
// #include <qb/uuid.h>    // For qb::uuid and qb::generate_random_uuid -- Linter still complains, assume http.h or other includes cover it
#include <memory>
#include <string>
#include <vector>
#include <functional> // For std::function
#include <sstream> // For std::ostringstream
// #include <future> // Removed due to single-threaded refactor
// #include <thread> // Removed due to single-threaded refactor

// --- Helper Classes for Middleware Router Tests ---

// Simple Task Executor (can be copied from test-router-async.cpp or refined)
class TaskExecutor {
public:
    void addTask(std::function<void()> task) {
        _tasks.push_back(std::move(task));
    }

    void processAllTasks() {
        std::vector<std::function<void()>> tasks_to_process = _tasks;
        _tasks.clear();
        for (auto& task : tasks_to_process) {
            task();
        }
    }
    
    void processTaskAtIndex(size_t index) {
        if (index < _tasks.size()) {
            auto task = _tasks[index];
            _tasks.erase(_tasks.begin() + index);
            task();
        }
    }

    size_t getPendingTaskCount() const {
        return _tasks.size();
    }
    
    void clearTasks() {
        _tasks.clear();
    }

private:
    std::vector<std::function<void()>> _tasks;
};

// Mock Session for Middleware Router Tests
struct MockMiddlewareSession {
    qb::http::Response _response;
    qb::uuid _session_id = qb::generate_random_uuid();
    std::ostringstream _execution_trace; // To trace middleware execution
    bool _final_handler_called = false;

    qb::http::Response& get_response_ref() { return _response; }

    MockMiddlewareSession& operator<<(const qb::http::Response& resp) {
        _response = resp;
        return *this;
    }

    [[nodiscard]] const qb::uuid& id() const { return _session_id; }

    void reset() {
        _response = qb::http::Response();
        _execution_trace.str("");
        _execution_trace.clear();
        _final_handler_called = false;
    }

    void trace(const std::string& id) {
        if (!_execution_trace.str().empty()) {
            _execution_trace << ";";
        }
        _execution_trace << id;
    }

    std::string get_trace() const {
        return _execution_trace.str();
    }
};

// --- Test Middleware Implementations ---

// Base class for Test Middlewares to provide an ID
class BaseTestMiddleware : public qb::http::IMiddleware<MockMiddlewareSession> {
protected:
    std::string _id;
public:
    explicit BaseTestMiddleware(std::string id) : _id(std::move(id)) {}
    std::string name() const override { return _id; }
    void cancel() noexcept override {}
};

// Synchronous middleware that appends its ID and calls next
class SyncAppendingMiddleware : public BaseTestMiddleware {
public:
    explicit SyncAppendingMiddleware(std::string id) : BaseTestMiddleware(std::move(id)) {}

    void process(std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) override {
        if (ctx && ctx->session()) {
            ctx->session()->trace(_id);
        }
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }
};

// Asynchronous middleware that appends ID and calls next via TaskExecutor
class AsyncAppendingMiddleware : public BaseTestMiddleware {
private:
    TaskExecutor* _executor;
public:
    AsyncAppendingMiddleware(std::string id, TaskExecutor* executor) 
        : BaseTestMiddleware(std::move(id)), _executor(executor) {}

    void process(std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) override {
        if (!_executor) {
            if (ctx->session()) ctx->session()->trace(_id + "_NO_EXECUTOR");
            ctx->complete(qb::http::AsyncTaskResult::ERROR); // Cannot proceed
            return;
        }
        if (ctx && ctx->session()) {
            ctx->session()->trace(_id + "_handle");
        }
        auto shared_ctx = ctx;
        _executor->addTask([shared_ctx, id = _id]() {
            if (shared_ctx->is_cancelled()) { // Check for cancellation
                // If cancelled, the context should already be finalizing or finalized.
                // We might not even need to trace here, or trace something specific like "task_cancelled_before_execution"
                // std::cerr << "Async task for " << id << " was cancelled before execution." << std::endl;
                return; 
            }
            if (shared_ctx && shared_ctx->session()) {
                shared_ctx->session()->trace(id + "_task");
            }
            shared_ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
        });
    }
};

// Synchronous middleware that short-circuits
class SyncShortCircuitMiddleware : public BaseTestMiddleware {
private:
    int _status_code_int;
public:
    SyncShortCircuitMiddleware(std::string id, int status_code = HTTP_STATUS_OK) 
        : BaseTestMiddleware(std::move(id)), _status_code_int(status_code) {}

    void process(std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) override {
        if (ctx && ctx->session()) {
            ctx->session()->trace(_id);
        }
        ctx->response().status_code = static_cast<qb::http::status>(_status_code_int);
        ctx->response().body() = _id + " short-circuited";
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    }
};

// Synchronous middleware that signals an error
class SyncErrorMiddleware : public BaseTestMiddleware {
public:
    explicit SyncErrorMiddleware(std::string id) : BaseTestMiddleware(std::move(id)) {}

    void process(std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) override {
        if (ctx && ctx->session()) {
            ctx->session()->trace(_id);
        }
        ctx->response().status_code = qb::http::status::HTTP_STATUS_INTERNAL_SERVER_ERROR;
        ctx->response().body() = _id + " signaled error";
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
    }
};

// Asynchronous middleware that short-circuits
class AsyncShortCircuitMiddleware : public BaseTestMiddleware {
private:
    TaskExecutor* _executor;
    int _status_code_int;
public:
    AsyncShortCircuitMiddleware(std::string id, TaskExecutor* executor, int status_code = HTTP_STATUS_OK)
        : BaseTestMiddleware(std::move(id)), _executor(executor), _status_code_int(status_code) {}

    void process(std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) override {
        if (!_executor) {
            if (ctx->session()) ctx->session()->trace(_id + "_NO_EXECUTOR");
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
            return;
        }
        if (ctx && ctx->session()) {
            ctx->session()->trace(_id + "_handle");
        }
        auto shared_ctx = ctx;
        _executor->addTask([shared_ctx, id = _id, status = _status_code_int]() {
            if (shared_ctx && shared_ctx->session()) {
                shared_ctx->session()->trace(id + "_task");
            }
            shared_ctx->response().status_code = static_cast<qb::http::status>(status);
            shared_ctx->response().body() = id + " short-circuited asynchronously";
            shared_ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
        });
    }
};

// Asynchronous middleware that signals an error
class AsyncErrorMiddleware : public BaseTestMiddleware {
private:
    TaskExecutor* _executor;
public:
    AsyncErrorMiddleware(std::string id, TaskExecutor* executor)
        : BaseTestMiddleware(std::move(id)), _executor(executor) {}

    void process(std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) override {
        if (!_executor) {
            if (ctx->session()) ctx->session()->trace(_id + "_NO_EXECUTOR");
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
            return;
        }
        if (ctx && ctx->session()) {
            ctx->session()->trace(_id + "_handle");
        }
        auto shared_ctx = ctx;
        _executor->addTask([shared_ctx, id = _id]() {
            if (shared_ctx && shared_ctx->session()) {
                shared_ctx->session()->trace(id + "_task");
            }
            shared_ctx->response().status_code = qb::http::status::HTTP_STATUS_INTERNAL_SERVER_ERROR;
            shared_ctx->response().body() = id + " signaled error asynchronously";
            shared_ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });
    }
};

// --- Helper Middleware for Cancellation Tests ---

class CancellableSyncAppendingMiddleware : public SyncAppendingMiddleware {
public:
    bool cancel_called = false;
    std::function<void(std::shared_ptr<qb::http::Context<MockMiddlewareSession>>)> on_handle_sync_point_for_test;

    CancellableSyncAppendingMiddleware(std::string id) : SyncAppendingMiddleware(std::move(id)) {}

    void process(std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) override {
        if (ctx && ctx->session()) {
            ctx->session()->trace(_id);
        }

        // Hook for test to intervene (e.g., to cancel the context)
        if (on_handle_sync_point_for_test) {
            on_handle_sync_point_for_test(ctx);
        }

        // If the context was cancelled by the hook, complete() should respect that.
        if (!ctx->is_cancelled()) { // Only proceed if not cancelled by the hook
            ctx->complete(qb::http::AsyncTaskResult::CONTINUE); 
        } else {
            // If cancelled by the hook, the context's complete(CANCELLED) should have already been called by ctx->cancel().
            // No need to call complete() again here as it might interfere or be redundant.
            // The Context::cancel mechanism should handle the finalization.
            std::cerr << "CancellableSyncAppendingMiddleware [" << _id << "]: Context was cancelled by test hook. Not calling complete(CONTINUE)." << std::endl;
        }
    }

    void cancel() noexcept override {
        cancel_called = true;
        // It's hard to reliably trace from here if the context isn't stored, 
        // as cancel() can be called when the task isn't actively handling a context.
        // For testing, we'll rely on the cancel_called flag.
        // std::cerr << "Cancel called for: " << _id << std::endl; // For debugging test failures
    }
};

class CancellableAsyncAppendingMiddleware : public AsyncAppendingMiddleware {
public:
    bool cancel_called = false;

    CancellableAsyncAppendingMiddleware(std::string id, TaskExecutor* executor)
        : AsyncAppendingMiddleware(std::move(id), executor) {}

    void cancel() noexcept override {
        cancel_called = true;
        // std::cerr << "Cancel called for: " << _id << std::endl;
    }
    // The base AsyncAppendingMiddleware posts a task. If Context::cancel() is called 
    // while that task is pending or executing, the Context should handle it.
    // The IAsyncTask::cancel() is for the RouterCore to notify the task.
};

// --- Test Suite ---
class RouterMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockMiddlewareSession> _mock_session;
    qb::http::Router<MockMiddlewareSession> _router;
    TaskExecutor _task_executor;

    void SetUp() override {
        _mock_session = std::make_shared<MockMiddlewareSession>();
        _router = qb::http::Router<MockMiddlewareSession>(); // Re-initialize router
        _task_executor.clearTasks(); // Clear tasks for each test
    }

    void TearDown() override {
        // Clean up if necessary
    }

    qb::http::Request create_request(qb::http::method method_val, const std::string& target_path_str) {
        qb::http::Request req;
        req.method = method_val;
        req.uri() = qb::io::uri(target_path_str); // Correctly set URI via assignment to reference
        req.major_version = 1; // Set HTTP version directly
        req.minor_version = 1;
        return req;
    }

    // Final handler for routes
    qb::http::RouteHandlerFn<MockMiddlewareSession> final_handler(const std::string& handler_id = "final_handler") {
        return [handler_id](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
            if (ctx && ctx->session()) {
                ctx->session()->trace(handler_id);
                ctx->session()->_final_handler_called = true;
            }
            ctx->response().status_code = qb::http::status::HTTP_STATUS_OK;
            ctx->response().body() = handler_id + " executed";
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
        };
    }
};

// --- Basic Synchronous Middleware Tests (Router Level) ---

TEST_F(RouterMiddlewareTest, SingleSyncMiddleware) {
    _router.use(std::make_shared<SyncAppendingMiddleware>("mw1"));
    _router.get("/test", final_handler());
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/test"));
    
    EXPECT_EQ(_mock_session->get_trace(), "mw1;final_handler");
    EXPECT_TRUE(_mock_session->_final_handler_called);
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_OK);
}

TEST_F(RouterMiddlewareTest, MultipleSyncMiddlewareOrder) {
    _router.use(std::make_shared<SyncAppendingMiddleware>("mw1"));
    _router.use(std::make_shared<SyncAppendingMiddleware>("mw2"));
    _router.use(std::make_shared<SyncAppendingMiddleware>("mw3"));
    _router.get("/test", final_handler());
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/test"));
    
    EXPECT_EQ(_mock_session->get_trace(), "mw1;mw2;mw3;final_handler");
    EXPECT_TRUE(_mock_session->_final_handler_called);
}

TEST_F(RouterMiddlewareTest, SyncMiddlewareShortCircuit) {
    _router.use(std::make_shared<SyncAppendingMiddleware>("mw1"));
    _router.use(std::make_shared<SyncShortCircuitMiddleware>("mw_sc", HTTP_STATUS_ACCEPTED));
    _router.use(std::make_shared<SyncAppendingMiddleware>("mw3_never_reached"));
    _router.get("/test", final_handler("handler_never_reached"));
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/test"));
    
    EXPECT_EQ(_mock_session->get_trace(), "mw1;mw_sc");
    EXPECT_FALSE(_mock_session->_final_handler_called);
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_ACCEPTED);
    EXPECT_EQ(_mock_session->_response.body().template as<std::string>(), "mw_sc short-circuited");
}

TEST_F(RouterMiddlewareTest, SyncMiddlewareError) {
    _router.use(std::make_shared<SyncAppendingMiddleware>("mw1"));
    _router.use(std::make_shared<SyncErrorMiddleware>("mw_err"));
    _router.use(std::make_shared<SyncAppendingMiddleware>("mw3_never_reached"));
    _router.get("/test", final_handler("handler_never_reached"));
    // Define a simple error handler for the router to check if it's called
    _router.set_error_task_chain(std::list<std::shared_ptr<qb::http::IAsyncTask<MockMiddlewareSession>>>{
        std::make_shared<qb::http::MiddlewareTask<MockMiddlewareSession>>(
            std::make_shared<qb::http::FunctionalMiddleware<MockMiddlewareSession>>([](auto ctx, auto /*next*/){ // Assuming next is not used based on lambda body
                ctx->session()->trace("error_handler_task");
                // Don't change status if already an error status from mw_err
                if(ctx->response().status_code != qb::http::status::HTTP_STATUS_INTERNAL_SERVER_ERROR) {
                     ctx->response().status_code = qb::http::status::HTTP_STATUS_INTERNAL_SERVER_ERROR;
                }
                ctx->response().body() = "Processed by error_handler_task";
                ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
            }, "error_handler_task")
        )
    });
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/test"));
    
    EXPECT_EQ(_mock_session->get_trace(), "mw1;mw_err;error_handler_task");
    EXPECT_FALSE(_mock_session->_final_handler_called);
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_mock_session->_response.body().template as<std::string>(), "Processed by error_handler_task");
}

// --- Basic Asynchronous Middleware Tests (Router Level) ---

TEST_F(RouterMiddlewareTest, SingleAsyncMiddleware) {
    _router.use(std::make_shared<AsyncAppendingMiddleware>("async_mw1", &_task_executor));
    _router.get("/test", final_handler());
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/test"));
    EXPECT_EQ(_mock_session->get_trace(), "async_mw1_handle"); // Only handle part runs synchronously
    EXPECT_FALSE(_mock_session->_final_handler_called);
    
    _task_executor.processAllTasks(); // Process the async part
    EXPECT_EQ(_mock_session->get_trace(), "async_mw1_handle;async_mw1_task;final_handler");
    EXPECT_TRUE(_mock_session->_final_handler_called);
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_OK);
}

TEST_F(RouterMiddlewareTest, MultipleAsyncMiddlewareOrder) {
    _router.use(std::make_shared<AsyncAppendingMiddleware>("async_mw1", &_task_executor));
    _router.use(std::make_shared<AsyncAppendingMiddleware>("async_mw2", &_task_executor));
    _router.get("/test", final_handler());
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/test"));
    EXPECT_EQ(_mock_session->get_trace(), "async_mw1_handle");
    
    _task_executor.processAllTasks(); // Process async_mw1's task
    EXPECT_EQ(_mock_session->get_trace(), "async_mw1_handle;async_mw1_task;async_mw2_handle");

    _task_executor.processAllTasks(); // Process async_mw2's task
    EXPECT_EQ(_mock_session->get_trace(), "async_mw1_handle;async_mw1_task;async_mw2_handle;async_mw2_task;final_handler");
    EXPECT_TRUE(_mock_session->_final_handler_called);
}

TEST_F(RouterMiddlewareTest, MixedSyncAndAsyncMiddlewareOrder) {
    _router.use(std::make_shared<SyncAppendingMiddleware>("sync1"));
    _router.use(std::make_shared<AsyncAppendingMiddleware>("async1", &_task_executor));
    _router.use(std::make_shared<SyncAppendingMiddleware>("sync2"));
    _router.get("/test", final_handler());
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/test"));
    // sync1 runs, then async1_handle runs and posts a task
    EXPECT_EQ(_mock_session->get_trace(), "sync1;async1_handle"); 
    
    _task_executor.processAllTasks(); // Process async1's task
    // async1_task runs, then sync2 runs, then final_handler
    EXPECT_EQ(_mock_session->get_trace(), "sync1;async1_handle;async1_task;sync2;final_handler");
    EXPECT_TRUE(_mock_session->_final_handler_called);
}

// --- RouteGroup Level Middleware Tests ---

TEST_F(RouterMiddlewareTest, GroupSingleSyncMiddleware) {
    auto group = _router.group("/group");
    group->use(std::make_shared<SyncAppendingMiddleware>("group_mw1"));
    group->get("/test", final_handler());
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/group/test"));
    EXPECT_EQ(_mock_session->get_trace(), "group_mw1;final_handler");
    EXPECT_TRUE(_mock_session->_final_handler_called);
}

TEST_F(RouterMiddlewareTest, RouterAndGroupSyncMiddleware) {
    _router.use(std::make_shared<SyncAppendingMiddleware>("router_mw1"));
    auto group = _router.group("/group");
    group->use(std::make_shared<SyncAppendingMiddleware>("group_mw1"));
    group->get("/test", final_handler());
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/group/test"));
    // Router middleware runs first, then group middleware
    EXPECT_EQ(_mock_session->get_trace(), "router_mw1;group_mw1;final_handler");
}

TEST_F(RouterMiddlewareTest, RouterAsyncAndGroupSyncMiddleware) {
    _router.use(std::make_shared<AsyncAppendingMiddleware>("router_async_mw1", &_task_executor));
    auto group = _router.group("/group");
    group->use(std::make_shared<SyncAppendingMiddleware>("group_sync_mw1"));
    group->get("/test", final_handler());
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/group/test"));
    EXPECT_EQ(_mock_session->get_trace(), "router_async_mw1_handle");
    
    _task_executor.processAllTasks();
    EXPECT_EQ(_mock_session->get_trace(), "router_async_mw1_handle;router_async_mw1_task;group_sync_mw1;final_handler");
}

TEST_F(RouterMiddlewareTest, GroupMiddlewareNotAppliedToOtherRoutes) {
    _router.use(std::make_shared<SyncAppendingMiddleware>("router_mw1"));
    auto group = _router.group("/group");
    group->use(std::make_shared<SyncAppendingMiddleware>("group_mw1"));
    group->get("/test", final_handler("group_handler"));
    
    _router.get("/other", final_handler("other_handler"));
    _router.compile();

    // Test group route
    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/group/test"));
    EXPECT_EQ(_mock_session->get_trace(), "router_mw1;group_mw1;group_handler");
    
    _mock_session->reset(); // Reset session for next route call

    // Test other route
    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/other"));
    EXPECT_EQ(_mock_session->get_trace(), "router_mw1;other_handler"); // group_mw1 should not be here
}

// TODO: Add tests for async short-circuit and async error middleware
// TODO: Add tests for middleware on nested groups.

TEST_F(RouterMiddlewareTest, AsyncMiddlewareShortCircuit) {
    _router.use(std::make_shared<AsyncAppendingMiddleware>("async_mw1", &_task_executor));
    _router.use(std::make_shared<AsyncShortCircuitMiddleware>("async_sc", &_task_executor, HTTP_STATUS_CREATED));
    _router.use(std::make_shared<AsyncAppendingMiddleware>("async_mw3_never_reached", &_task_executor));
    _router.get("/test", final_handler("handler_never_reached"));
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/test"));
    EXPECT_EQ(_mock_session->get_trace(), "async_mw1_handle");
    
    _task_executor.processAllTasks(); // Process async_mw1's task, then async_sc_handle
    EXPECT_EQ(_mock_session->get_trace(), "async_mw1_handle;async_mw1_task;async_sc_handle");
    
    _task_executor.processAllTasks(); // Process async_sc's task which short-circuits
    EXPECT_EQ(_mock_session->get_trace(), "async_mw1_handle;async_mw1_task;async_sc_handle;async_sc_task");
    EXPECT_FALSE(_mock_session->_final_handler_called);
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_CREATED);
    EXPECT_EQ(_mock_session->_response.body().template as<std::string>(), "async_sc short-circuited asynchronously");
}

TEST_F(RouterMiddlewareTest, AsyncMiddlewareError) {
    _router.use(std::make_shared<AsyncAppendingMiddleware>("async_mw1", &_task_executor));
    _router.use(std::make_shared<AsyncErrorMiddleware>("async_err_mw", &_task_executor));
    _router.use(std::make_shared<AsyncAppendingMiddleware>("async_mw3_never_reached", &_task_executor));
    _router.get("/test", final_handler("handler_never_reached"));

    _router.set_error_task_chain(std::list<std::shared_ptr<qb::http::IAsyncTask<MockMiddlewareSession>>>{
        std::make_shared<qb::http::MiddlewareTask<MockMiddlewareSession>>(
            std::make_shared<qb::http::FunctionalMiddleware<MockMiddlewareSession>>([](auto ctx, auto /*next*/){ // Assuming next is not used
                ctx->session()->trace("async_error_handler_task");
                if(ctx->response().status_code != qb::http::status::HTTP_STATUS_INTERNAL_SERVER_ERROR) {
                     ctx->response().status_code = qb::http::status::HTTP_STATUS_SERVICE_UNAVAILABLE; // Original was SERVICE_UNAVAILABLE, keeping it.
                }
                ctx->response().body() = "Processed by async_error_handler_task";
                ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
            }, "async_error_handler_task")
        )
    });
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/test"));
    EXPECT_EQ(_mock_session->get_trace(), "async_mw1_handle");
    
    _task_executor.processAllTasks(); // Process async_mw1's task, then async_err_mw_handle
    EXPECT_EQ(_mock_session->get_trace(), "async_mw1_handle;async_mw1_task;async_err_mw_handle");

    _task_executor.processAllTasks(); // Process async_err_mw's task which signals error
                                      // This should trigger the error handler chain.
    EXPECT_EQ(_mock_session->get_trace(), "async_mw1_handle;async_mw1_task;async_err_mw_handle;async_err_mw_task;async_error_handler_task");
    EXPECT_FALSE(_mock_session->_final_handler_called);
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_mock_session->_response.body().template as<std::string>(), "Processed by async_error_handler_task");
}

TEST_F(RouterMiddlewareTest, NestedGroupMiddleware) {
    _router.use(std::make_shared<SyncAppendingMiddleware>("router_mw"));
    auto group1 = _router.group("/group1");
    group1->use(std::make_shared<SyncAppendingMiddleware>("g1_mw"));
    
    auto group2 = group1->group("/group2");
    group2->use(std::make_shared<SyncAppendingMiddleware>("g2_mw"));
    group2->get("/test", final_handler("g2_handler"));

    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/group1/group2/test"));
    EXPECT_EQ(_mock_session->get_trace(), "router_mw;g1_mw;g2_mw;g2_handler");
    EXPECT_TRUE(_mock_session->_final_handler_called);
}

TEST_F(RouterMiddlewareTest, NestedGroupAsyncMiddleware) {
    _router.use(std::make_shared<SyncAppendingMiddleware>("router_sync"));
    auto group1 = _router.group("/g1");
    group1->use(std::make_shared<AsyncAppendingMiddleware>("g1_async", &_task_executor));
    
    auto group2 = group1->group("/g2");
    group2->use(std::make_shared<SyncAppendingMiddleware>("g2_sync"));
    group2->get("/test", final_handler("g2_handler"));

    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/g1/g2/test"));
    EXPECT_EQ(_mock_session->get_trace(), "router_sync;g1_async_handle");
    
    _task_executor.processAllTasks(); // Process g1_async's task
    EXPECT_EQ(_mock_session->get_trace(), "router_sync;g1_async_handle;g1_async_task;g2_sync;g2_handler");
    EXPECT_TRUE(_mock_session->_final_handler_called);
}

// --- Not Found Handler Tests ---

TEST_F(RouterMiddlewareTest, DefaultNotFoundHandler) {
    _router.get("/exists", final_handler("handler_exists"));
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/does_not_exist"));
    _task_executor.processAllTasks(); // Process any async tasks if they were part of a (non-existent) 404 chain

    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND);
    EXPECT_EQ(_mock_session->_response.body().template as<std::string>(), "404 Not Found (Default)");
}

TEST_F(RouterMiddlewareTest, CustomNotFoundHandler) {
    _router.set_not_found_handler([](auto ctx){
        ctx->session()->trace("custom_404_handler");
        ctx->response().status_code = HTTP_STATUS_NOT_FOUND;
        ctx->response().body() = "Custom 404 Page";
        ctx->complete();
    });
    _router.get("/exists", final_handler("handler_exists"));
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/does_not_exist"));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND);
    EXPECT_EQ(_mock_session->_response.body().template as<std::string>(), "Custom 404 Page");
    EXPECT_EQ(_mock_session->get_trace(), "custom_404_handler"); // The custom handler itself is wrapped in DefaultOrCustomNotFoundHandler
}

TEST_F(RouterMiddlewareTest, GlobalMiddlewareBeforeCustomNotFoundHandler) {
    _router.use(std::make_shared<SyncAppendingMiddleware>("global_mw1"));
    _router.set_not_found_handler([](auto ctx){
        ctx->session()->trace("custom_404_handler");
        ctx->response().status_code = HTTP_STATUS_NOT_FOUND;
        ctx->response().body() = "Custom 404 With Global MW";
        ctx->complete();
    });
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/will_be_404"));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND);
    EXPECT_EQ(_mock_session->get_trace(), "global_mw1;custom_404_handler");
}

TEST_F(RouterMiddlewareTest, ErrorInCustomNotFoundHandlerIsFatal) {
    _router.set_not_found_handler([](auto ctx){
        ctx->session()->trace("custom_404_causes_error");
        // This handler will signal FATAL_SPECIAL_HANDLER_ERROR
        ctx->complete(qb::http::AsyncTaskResult::FATAL_SPECIAL_HANDLER_ERROR);
    });
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/any_path_for_404"));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_mock_session->get_trace(), "custom_404_causes_error");
    // Body might be empty or default for 500, depending on how finalize_processing handles it
}

TEST_F(RouterMiddlewareTest, ErrorInGlobalMiddlewareDuringNotFoundProcessing) {
    _router.use(std::make_shared<SyncErrorMiddleware>("global_error_mw")); // This will cause an error
    _router.set_not_found_handler([](auto ctx){ // This 404 handler should not be reached
        ctx->session()->trace("custom_404_not_reached");
        ctx->complete();
    });
    _router.set_error_task_chain(std::list<std::shared_ptr<qb::http::IAsyncTask<MockMiddlewareSession>>>{
        std::make_shared<qb::http::MiddlewareTask<MockMiddlewareSession>>(
            std::make_shared<qb::http::FunctionalMiddleware<MockMiddlewareSession>>([](auto ctx, auto /*next*/){
                ctx->session()->trace("main_error_handler_after_404_global_mw_error");
                ctx->response().status_code = qb::http::status::HTTP_STATUS_INTERNAL_SERVER_ERROR;
                ctx->response().body() = "Error in global_mw during 404 processing, caught by main error handler";
                ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
            }, "main_error_handler_after_404_global_mw_error")
        )
    });
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/triggers_404_then_error"));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->get_trace(), "global_error_mw;main_error_handler_after_404_global_mw_error");
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_mock_session->_response.body().template as<std::string>(), "Error in global_mw during 404 processing, caught by main error handler");
}

// --- Error in Error Handler Test ---

TEST_F(RouterMiddlewareTest, ErrorInUserErrorHandlerIsFatal) {
    _router.use(std::make_shared<SyncErrorMiddleware>("trigger_initial_error")); // To trigger the error chain
    _router.set_error_task_chain(std::list<std::shared_ptr<qb::http::IAsyncTask<MockMiddlewareSession>>>{
        std::make_shared<qb::http::MiddlewareTask<MockMiddlewareSession>>(
            std::make_shared<qb::http::FunctionalMiddleware<MockMiddlewareSession>>([](auto ctx, auto /*next*/){
                ctx->session()->trace("faulty_error_handler");
                // This error handler itself signals an error
                ctx->complete(qb::http::AsyncTaskResult::ERROR); 
            }, "faulty_error_handler")
        )
    });
    _router.compile();

    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/test"));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->get_trace(), "trigger_initial_error;faulty_error_handler");
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    // Body will likely be what `faulty_error_handler` set before erroring, or empty if status set late.
    // The key is that it doesn't loop and results in a 500.
}

// --- Cancellation Tests ---

TEST_F(RouterMiddlewareTest, CancellationDuringSyncGlobalMiddleware) {
    auto mw1 = std::make_shared<CancellableSyncAppendingMiddleware>("mw1_cancellable");
    // Setup the hook for mw1 to cancel the context during its handle method
    mw1->on_handle_sync_point_for_test = [](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx_inside_handle) {
        if (ctx_inside_handle) {
            ctx_inside_handle->cancel("Test initiated cancellation during mw1 handle");
        }
    };

    _router.use(mw1);
    _router.use(std::make_shared<SyncAppendingMiddleware>("mw2_never_reached"));
    _router.get("/test", final_handler("handler_never_reached"));
    _router.compile();

    // Route the request. The cancellation will happen inside mw1's handle method.
    auto ctx_ptr = _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/test"));
    // ctx_ptr might be null if routing itself failed catastrophically before even starting the chain, 
    // but given the setup, it should be valid if mw1->handle was reached.
    // The assertions below will cover the outcome.
    
    _task_executor.processAllTasks(); // Should be no async tasks involved here.

    EXPECT_TRUE(mw1->cancel_called); 
    EXPECT_EQ(_mock_session->get_trace(), "mw1_cancellable"); // mw1 runs and traces, then cancelled
    EXPECT_FALSE(_mock_session->_final_handler_called); // Should not be reached
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE); // Default cancellation status
}

TEST_F(RouterMiddlewareTest, CancellationDuringAsyncGlobalMiddleware_BeforeAsyncTaskFinishes) {
    auto async_mw1 = std::make_shared<CancellableAsyncAppendingMiddleware>("async_mw1_cancellable", &_task_executor);
    _router.use(async_mw1);
    _router.use(std::make_shared<SyncAppendingMiddleware>("mw2_never_reached"));
    _router.get("/test", final_handler("handler_never_reached"));
    _router.compile();

    auto ctx_ptr = _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/test"));
    ASSERT_NE(ctx_ptr, nullptr) << "Context pointer should not be null.";

    // At this point, async_mw1->process() has run and posted its task to _task_executor.
    // The trace reflects only the synchronous part of async_mw1.
    EXPECT_EQ(_mock_session->get_trace(), "async_mw1_cancellable_handle");
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 1); // Task for async_mw1_cancellable_task is pending

    ctx_ptr->cancel("Cancelled before async task completes");

    // Try to process tasks - the cancelled context should prevent the async task part from running.
    // The TaskExecutor will still run the lambda, but the lambda should respect ctx->is_cancelled() or ctx->complete() should handle it.
    // Our AsyncAppendingMiddleware completes with CONTINUE. Context::complete should then see it's cancelled and finalize.
    _task_executor.processAllTasks(); 

    EXPECT_TRUE(async_mw1->cancel_called);
    // The trace should remain as it was after the _handle part, as the _task part should not execute its trace or proceed.
    EXPECT_EQ(_mock_session->get_trace(), "async_mw1_cancellable_handle"); 
    EXPECT_FALSE(_mock_session->_final_handler_called);
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 0); // All tasks from executor should be processed or discarded
}

TEST_F(RouterMiddlewareTest, CancellationDuringSyncGroupMiddleware) {
    auto group = _router.group("/group");
    auto group_mw = std::make_shared<CancellableSyncAppendingMiddleware>("group_mw_cancellable");
    // Setup the hook for group_mw to cancel the context
    group_mw->on_handle_sync_point_for_test = [](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx_inside_handle) {
        if (ctx_inside_handle) {
            ctx_inside_handle->cancel("Test initiated cancellation during group_mw handle");
        }
    };

    group->use(group_mw);
    group->use(std::make_shared<SyncAppendingMiddleware>("group_mw2_never_reached"));
    group->get("/test", final_handler("handler_never_reached"));
    _router.compile();

    auto ctx_ptr = _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/group/test"));
    // Similar to the global sync test, ctx_ptr validity is mostly an intermediate check.
    // The actual outcome is verified by assertions.

    _task_executor.processAllTasks(); // No async tasks here.

    EXPECT_TRUE(group_mw->cancel_called);
    EXPECT_EQ(_mock_session->get_trace(), "group_mw_cancellable");
    EXPECT_FALSE(_mock_session->_final_handler_called);
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);
}

TEST_F(RouterMiddlewareTest, CancellationDuringAsyncGroupMiddleware_BeforeAsyncTaskFinishes) {
    auto group = _router.group("/group");
    auto async_group_mw = std::make_shared<CancellableAsyncAppendingMiddleware>("async_group_mw_cancellable", &_task_executor);
    group->use(async_group_mw);
    group->use(std::make_shared<SyncAppendingMiddleware>("group_mw2_never_reached"));
    group->get("/test", final_handler("handler_never_reached"));
    _router.compile();

    auto ctx_ptr = _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/group/test"));
    ASSERT_NE(ctx_ptr, nullptr) << "Context pointer should not be null.";

    EXPECT_EQ(_mock_session->get_trace(), "async_group_mw_cancellable_handle");
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 1);

    ctx_ptr->cancel("Cancelled before async group task completes");

    _task_executor.processAllTasks();

    EXPECT_TRUE(async_group_mw->cancel_called);
    EXPECT_EQ(_mock_session->get_trace(), "async_group_mw_cancellable_handle");
    EXPECT_FALSE(_mock_session->_final_handler_called);
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 0);
}

// --- Advanced Middleware Scenarios ---

// Test for FunctionalMiddleware acting as "around" middleware (pre and post processing)
TEST_F(RouterMiddlewareTest, FunctionalMiddlewareAroundBehavior) {
    _router.use(
        std::make_shared<qb::http::FunctionalMiddleware<MockMiddlewareSession>>(
            [](auto ctx, auto next_fn) {
                ctx->request().set_header("X-Pre-Process", "handled_by_around_mw");
                if(ctx->session()) ctx->session()->trace("around_mw_pre_next_fn"); // Trace pre

                next_fn(); // Call the next task in the chain
                
                // This part executes after the next_fn() chain has processed.
                // It will modify ctx->response().
                ctx->response().set_header("X-Post-Process-On-Ctx", "handled_by_around_mw_on_ctx"); 
                if(ctx->session()) ctx->session()->trace("around_mw_post_next_fn"); // Trace post
            },
            "AroundFunctionalMiddleware"
        )
    );

    _router.use(std::make_shared<SyncAppendingMiddleware>("inner_mw")); // To check request header

    _router.get("/test_around", [this](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
        // Check request header set by the "around" middleware before next_fn()
        EXPECT_EQ(ctx->request().header("X-Pre-Process"), "handled_by_around_mw");
        
        if (ctx && ctx->session()) {
            ctx->session()->trace("final_around_handler");
            ctx->session()->_final_handler_called = true;
        }
        ctx->response().status_code = qb::http::status::HTTP_STATUS_OK;
        ctx->response().body() = "final_around_handler executed";
        // Check that X-Post-Process-On-Ctx is NOT YET on the response when handler is running
        EXPECT_TRUE(ctx->response().header("X-Post-Process-On-Ctx").empty());
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    });

    _router.compile();
    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/test_around"));
    _task_executor.processAllTasks(); // Process any async tasks

    EXPECT_TRUE(_mock_session->_final_handler_called);
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_OK);
    
    // Verify the execution trace to show the pre and post processing code ran in the middleware lambda
    EXPECT_EQ(_mock_session->get_trace(), "around_mw_pre_next_fn;inner_mw;final_around_handler;around_mw_post_next_fn"); 
    
    // Explicitly check that X-Post-Process-On-Ctx is NOT on the session's final response, 
    // confirming current behavior where late modifications to ctx->response() are not reflected
    // in _mock_session->_response after finalize_processing.
    EXPECT_TRUE(_mock_session->_response.header("X-Post-Process-On-Ctx").empty());
    
    // Also check that the original X-Post-Process (if it was ever set on session response) is not there
    EXPECT_TRUE(_mock_session->_response.header("X-Post-Process").empty()); 
}

// Test for FunctionalMiddleware conditionally exiting early
TEST_F(RouterMiddlewareTest, FunctionalMiddlewareConditionalEarlyExit) {
    _router.use(
        std::make_shared<qb::http::FunctionalMiddleware<MockMiddlewareSession>>(
            [](auto ctx, auto next_fn) {
                if (ctx->request().has_header("X-Stop-Early")) {
                    ctx->response().status_code = qb::http::status::HTTP_STATUS_IM_A_TEAPOT;
                    ctx->response().body() = "Stopped early by Functional MW";
                    ctx->complete(qb::http::AsyncTaskResult::COMPLETE); // Short-circuit
                } else {
                    next_fn(); // Continue processing
                }
            },
            "ConditionalFunctionalMiddleware"
        )
    );

    _router.use(std::make_shared<SyncAppendingMiddleware>("mw_after_conditional"));
    _router.get("/test_conditional_exit", final_handler("handler_for_conditional"));
    _router.compile();

    // --- Case 1: Middleware stops early ---    
    _mock_session->reset();
    qb::http::Request req_stop = create_request(qb::http::method::HTTP_GET, "/test_conditional_exit");
    req_stop.set_header("X-Stop-Early", "true");
    _router.route(_mock_session, std::move(req_stop));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_IM_A_TEAPOT);
    EXPECT_EQ(_mock_session->_response.body().template as<std::string>(), "Stopped early by Functional MW");
    EXPECT_FALSE(_mock_session->_final_handler_called); // Handler and subsequent MW should not run
    EXPECT_TRUE(_mock_session->get_trace().empty()); // ConditionalFunctionalMiddleware does not trace, nor does mw_after_conditional or handler

    // --- Case 2: Middleware continues ---    
    _mock_session->reset();
    qb::http::Request req_continue = create_request(qb::http::method::HTTP_GET, "/test_conditional_exit");
    // No X-Stop-Early header
    _router.route(_mock_session, std::move(req_continue));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_TRUE(_mock_session->_final_handler_called);
    EXPECT_EQ(_mock_session->get_trace(), "mw_after_conditional;handler_for_conditional");
}

// Test for state sharing between router-level middleware (e.g., via request headers)
TEST_F(RouterMiddlewareTest, MiddlewareStateSharingViaRequestHeaders) {
    _router.use(
        std::make_shared<qb::http::FunctionalMiddleware<MockMiddlewareSession>>(
            [](auto ctx, auto next_fn) {
                ctx->request().set_header("X-Data-From-MW-A", "hello_from_A");
                next_fn();
            },
            "Middleware_A_SetsHeader"
        )
    );

    _router.use(
        std::make_shared<qb::http::FunctionalMiddleware<MockMiddlewareSession>>(
            [](auto ctx, auto next_fn) {
                if (ctx->request().header("X-Data-From-MW-A") == "hello_from_A") {
                    ctx->request().set_header("X-Data-From-MW-B", "B_confirms_A"); // MW_B sets its own confirmation
                    if (ctx->session()) ctx->session()->trace("MW_B_processed_A_data");
                }
                next_fn();
            },
            "Middleware_B_ChecksHeader"
        )
    );

    _router.get("/test_mw_sharing", [this](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
        // Check if MW_B processed data from MW_A by looking for the header MW_B sets
        EXPECT_EQ(ctx->request().header("X-Data-From-MW-B"), "B_confirms_A");
        
        if (ctx && ctx->session()) {
            ctx->session()->trace("final_sharing_handler");
            ctx->session()->_final_handler_called = true;
        }
        ctx->response().status_code = qb::http::status::HTTP_STATUS_OK;
        ctx->response().body() = "final_sharing_handler executed";
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    });

    _router.compile();
    _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/test_mw_sharing"));
    _task_executor.processAllTasks();

    EXPECT_TRUE(_mock_session->_final_handler_called);
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->get_trace(), "MW_B_processed_A_data;final_sharing_handler");
}

// --- More Advanced Cancellation Scenarios ---

// Helper Middleware to trigger an error
class ErrorTriggerMiddleware : public BaseTestMiddleware {
public:
    explicit ErrorTriggerMiddleware(std::string id) : BaseTestMiddleware(std::move(id)) {}

    void process(std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) override {
        if(ctx->session()) ctx->session()->trace(_id);
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
    }
};

// Helper Middleware for testing cancellation within an error handler chain
class CancellableErrorHandlingMiddleware : public BaseTestMiddleware {
public:
    bool cancel_called = false;
    std::function<void(std::shared_ptr<qb::http::Context<MockMiddlewareSession>>)> on_handle_sync_point_for_test;

    CancellableErrorHandlingMiddleware(std::string id) : BaseTestMiddleware(std::move(id)) {}

    void process(std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) override {
        if(ctx->session()) ctx->session()->trace(_id + "_handling_error");
        
        if (on_handle_sync_point_for_test) {
            on_handle_sync_point_for_test(ctx);
        }

        if (!ctx->is_cancelled()) {
            ctx->response().status_code = qb::http::status::HTTP_STATUS_EXPECTATION_FAILED; // Some distinct status
            ctx->response().body() = _id + " processed error before any cancellation.";
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE); 
        } else {
             // If cancelled by the hook, Context::cancel mechanism should take over.
             // No explicit complete() here to avoid interference.
        }
    }

    void cancel() noexcept override {
        cancel_called = true;
        // if(_mock_session) _mock_session->trace(_id + "_cancel_called"); // Cannot access session here easily
    }
};

TEST_F(RouterMiddlewareTest, CancellationDuringErrorHandlingMiddleware) {
    auto error_trigger_mw = std::make_shared<ErrorTriggerMiddleware>("error_trigger");
    auto cancellable_error_handler_mw = std::make_shared<CancellableErrorHandlingMiddleware>("cancellable_error_mw");

    _router.use(error_trigger_mw); // This middleware will trigger the error chain
    
    _router.set_error_task_chain({ 
        std::make_shared<qb::http::MiddlewareTask<MockMiddlewareSession>>(cancellable_error_handler_mw) 
    });

    cancellable_error_handler_mw->on_handle_sync_point_for_test = 
        [](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx_in_error_handler) {
        if (ctx_in_error_handler) {
            ctx_in_error_handler->cancel("Test cancellation during error handling");
        }
    };

    _router.compile();
    
    auto ctx_ptr = _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/trigger_error_then_cancel"));
    _task_executor.processAllTasks();

    EXPECT_TRUE(cancellable_error_handler_mw->cancel_called);
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE); // Default cancellation status
    // The trace should show the error trigger, then the start of the error handler, but not its completion
    EXPECT_EQ(_mock_session->get_trace(), "error_trigger;cancellable_error_mw_handling_error"); 
}

TEST_F(RouterMiddlewareTest, CancellationDuringGlobalMiddlewareInNotFoundChain) {
    auto global_mw_cancellable = std::make_shared<CancellableSyncAppendingMiddleware>("global_mw_for_404_cancel");
    _router.use(global_mw_cancellable);

    // No route defined for "/path_to_trigger_404", so it will use the not_found_chain
    // which includes global middleware.

    global_mw_cancellable->on_handle_sync_point_for_test = 
        [](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx_in_global_mw) {
        if (ctx_in_global_mw) {
            // This middleware is now part of the not_found_chain execution
            ctx_in_global_mw->cancel("Test cancellation during global MW in 404 chain");
        }
    };

    _router.compile(); // Ensures global_mw_cancellable is part of the compiled not_found_tasks prefix

    auto ctx_ptr = _router.route(_mock_session, create_request(qb::http::method::HTTP_GET, "/path_to_trigger_404"));
    _task_executor.processAllTasks();

    EXPECT_TRUE(global_mw_cancellable->cancel_called);
    EXPECT_EQ(_mock_session->_response.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE); // Default cancellation status
    
    // The global middleware should trace its ID before being cancelled.
    // The default 404 handler (or any custom one) should not be reached.
    EXPECT_EQ(_mock_session->get_trace(), "global_mw_for_404_cancel"); 
} 
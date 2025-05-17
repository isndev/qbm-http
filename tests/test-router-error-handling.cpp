#include <gtest/gtest.h>
#include "../http.h" // Main include, expected to bring in qb::http::*, qb::io::uri, etc.


// Standard library - keep these as they are generally useful and explicit
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <optional>
#include <iostream> 
#include <list>     
#include <algorithm>
#include <stdexcept>

// --- Test Helper: TaskExecutor (inspired by test-router-async.cpp) ---
class TaskExecutor {
public:
    void addTask(std::function<void()> task) {
        _task_queue.push_back(std::move(task));
    }

    void processAllTasks() {
        while (!_task_queue.empty()) {
            auto task = std::move(_task_queue.front());
            _task_queue.pop_front();
            task(); // Execute the task
        }
    }

    bool hasTasks() const {
        return !_task_queue.empty();
    }
    size_t getPendingTaskCount() const {
        return _task_queue.size();
    }

private:
    std::list<std::function<void()>> _task_queue;
};

// --- Test Helper: MockErrorHandlingSession (inspired by MockAsyncSession and MockSession) ---
struct MockErrorHandlingSession {
    std::string _id = "test_error_session_id";
    qb::http::Response _response_received;
    bool _finalized_cb_called = false;
    std::vector<std::string> _executed_task_names;
    std::string _last_error_handler_name_executed; // Specific for error chain tests
    std::weak_ptr<qb::http::Context<MockErrorHandlingSession>> _last_context_seen;


    void record_task_execution(const std::string& task_name) {
        _executed_task_names.push_back(task_name);
    }

    void reset() {
        _response_received = qb::http::Response();
        _finalized_cb_called = false;
        _executed_task_names.clear();
        _last_error_handler_name_executed.clear();
        _last_context_seen.reset();
    }

    // Called by RouterCore's finalization callback
    MockErrorHandlingSession& operator<<(const qb::http::Response& resp) {
        _response_received = resp;
        _finalized_cb_called = true; // Mark that the finalization path was triggered
        return *this;
    }
};

// --- Test Helper: BaseTestTask (Common functionality for test tasks) ---
template <typename SessionType>
class BaseTestTask : public qb::http::IAsyncTask<SessionType> {
public:
    BaseTestTask(std::string name, std::shared_ptr<MockErrorHandlingSession> session_ref, TaskExecutor& executor_ref)
        : _name(std::move(name)), 
          _session_ref(session_ref), 
          _executor_ref(executor_ref), 
          _was_executed(false), 
          _was_cancelled(false) {
              // is_being_processed is inherited from IAsyncTask and defaults to false
          }

    std::string name() const override { return _name; }
    void cancel() override { _was_cancelled = true; /* More sophisticated cancellation can be added if needed */ }
    bool was_executed() const { return _was_executed; }
    bool was_cancelled() const { return _was_cancelled; }

protected:
    std::string _name;
    std::shared_ptr<MockErrorHandlingSession> _session_ref;
    TaskExecutor& _executor_ref;
    bool _was_executed;
    bool _was_cancelled;

    void record_execution(std::shared_ptr<qb::http::Context<SessionType>> ctx) {
        _was_executed = true;
        if (_session_ref) {
            _session_ref->record_task_execution(_name);
            _session_ref->_last_context_seen = ctx; // Keep track of the context this task saw
        }
    }
};

// --- Test Helper: ErrorSignalingTask ---
class ErrorSignalingTask : public BaseTestTask<MockErrorHandlingSession>, public qb::http::ICustomRoute<MockErrorHandlingSession> {
public:
    ErrorSignalingTask(std::string name, std::shared_ptr<MockErrorHandlingSession> session, TaskExecutor& executor)
        : BaseTestTask<MockErrorHandlingSession>(std::move(name), session, executor) {}

    // Method from ICustomRoute
    void process(std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) override {
        record_execution(ctx);
        _executor_ref.addTask([ctx, this]() { 
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });
    }

    // Method from IAsyncTask (can be removed if handle is sufficient, or call handle)
    void execute(std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) override {
        process(ctx);
    }

    // Explicitly provide get_name and cancel for ICustomRoute, delegating to BaseTestTask
    // This satisfies ICustomRoute if it declares these as pure virtuals independently of IAsyncTask
    std::string name() const override { return BaseTestTask<MockErrorHandlingSession>::name(); }
    void cancel() override { BaseTestTask<MockErrorHandlingSession>::cancel(); }
};

// --- Test Helper: ExceptionThrowingTask ---
class ExceptionThrowingTask : public BaseTestTask<MockErrorHandlingSession>, public qb::http::ICustomRoute<MockErrorHandlingSession> {
public:
    ExceptionThrowingTask(std::string name, std::shared_ptr<MockErrorHandlingSession> session, TaskExecutor& executor, std::string exception_message = "Test exception from task")
        : BaseTestTask<MockErrorHandlingSession>(std::move(name), session, executor), _exception_message(std::move(exception_message)) {}

    // Method from ICustomRoute
    void process(std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) override {
        record_execution(ctx);
        throw std::runtime_error(_exception_message); // Throw directly from handle
    }
    
    // Method from IAsyncTask
    void execute(std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) override {
         // If ICustomRoute::handle is the primary way this task is invoked by the new router,
         // this execute might become less relevant or could just call handle.
         // For now, to ensure behavior consistent with ICustomRoute, let it call handle.
         // However, the original design for ExceptionThrowingTask directly threw from execute.
         // Let's revert to throwing from execute for clarity if it's adapted by a task wrapper.
         // For CustomRouteAdapterTask, it calls ICustomRoute::handle.
         // So, throwing in process() is the correct path for ICustomRoute testing.
        process(ctx);
    }
    
    // Explicitly provide get_name and cancel for ICustomRoute
    std::string name() const override { return BaseTestTask<MockErrorHandlingSession>::name(); }
    void cancel() override { BaseTestTask<MockErrorHandlingSession>::cancel(); }

private:
    std::string _exception_message;
};

// --- Test Helper: NormalCompletingTask (can set response, acts as handler or error handler) ---
class NormalCompletingTask : public BaseTestTask<MockErrorHandlingSession>, public qb::http::ICustomRoute<MockErrorHandlingSession> {
public:
    NormalCompletingTask(std::string name, 
                         std::shared_ptr<MockErrorHandlingSession> session, 
                         TaskExecutor& executor, 
                         qb::http::status status_code = HTTP_STATUS_OK, // Corrected type and constant
                         std::string body = "OK",
                         bool is_error_path_handler = false) 
        : BaseTestTask<MockErrorHandlingSession>(std::move(name), session, executor), 
          _status_code(status_code), 
          _body(std::move(body)),
          _is_error_path_handler(is_error_path_handler) {}

    // Method from ICustomRoute
    void process(std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) override {
        record_execution(ctx);
        _executor_ref.addTask([ctx, name = _name, status_code_cap = _status_code, body_cap = _body, is_err_handler = _is_error_path_handler, session_h = _session_ref]() {
            ctx->response().status_code = status_code_cap;
            ctx->response().body() = body_cap;
            if (is_err_handler && session_h) {
                 session_h->_last_error_handler_name_executed = name;
            }
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
        });
    }

    // Method from IAsyncTask
    void execute(std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) override {
        process(ctx);
    }

    // Explicitly provide get_name and cancel for ICustomRoute
    std::string name() const override { return BaseTestTask<MockErrorHandlingSession>::name(); }
    void cancel() override { BaseTestTask<MockErrorHandlingSession>::cancel(); }

private:
    qb::http::status _status_code; // Corrected type
    std::string _body;
    bool _is_error_path_handler;
};

// --- Test Helper: GenericLambdaTask (for simple inline logic, can continue or complete) ---
class GenericLambdaTask : public BaseTestTask<MockErrorHandlingSession> {
public:
    using TaskLogicFn = std::function<void(std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx, TaskExecutor& executor)>;

    GenericLambdaTask(std::string name, std::shared_ptr<MockErrorHandlingSession> session, TaskExecutor& executor, TaskLogicFn logic_fn)
        : BaseTestTask<MockErrorHandlingSession>(std::move(name), session, executor), _logic_fn(std::move(logic_fn)) {}

    void execute(std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) override {
        record_execution(ctx);
        _logic_fn(ctx, _executor_ref); 
    }
private:
    TaskLogicFn _logic_fn;
};

// --- Test Helper: FatalSignalingTask (for FATAL_SPECIAL_HANDLER_ERROR) ---
class FatalSignalingTask : public BaseTestTask<MockErrorHandlingSession>, public qb::http::ICustomRoute<MockErrorHandlingSession> {
public:
    FatalSignalingTask(std::string name, std::shared_ptr<MockErrorHandlingSession> session, TaskExecutor& executor)
        : BaseTestTask<MockErrorHandlingSession>(std::move(name), session, executor) {}

    void process(std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) override {
        record_execution(ctx);
        _executor_ref.addTask([ctx, this]() { 
            ctx->complete(qb::http::AsyncTaskResult::FATAL_SPECIAL_HANDLER_ERROR);
        });
    }

    void execute(std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) override {
        process(ctx);
    }

    std::string name() const override { return BaseTestTask<MockErrorHandlingSession>::name(); }
    void cancel() override { BaseTestTask<MockErrorHandlingSession>::cancel(); }
};


// --- Test Fixture ---
class RouterErrorHandlingTest : public ::testing::Test {
protected:
    TaskExecutor _task_executor; 
    std::shared_ptr<qb::http::Router<MockErrorHandlingSession>> _router;
    std::shared_ptr<MockErrorHandlingSession> _session_ptr;

    void SetUp() override {
        _session_ptr = std::make_shared<MockErrorHandlingSession>();
        
        // Router's default constructor sets up its own on_request_finalized_callback for RouterCore.
        // That callback will eventually call _session_ptr->operator<<(response),
        // which is where we'll set _response_received and _finalized_cb_called.
        _router = std::make_shared<qb::http::Router<MockErrorHandlingSession>>();
    }

    void TearDown() override {
        if (_task_executor.hasTasks()) {
            _task_executor.processAllTasks();
        }
    }
    
    ~RouterErrorHandlingTest() noexcept override = default;

    void make_request(qb::http::method method_val, const std::string& path_str) {
        qb::http::Request req;
        req.method = method_val; // method_val is already qb::http::method, which is correct
        try {
            req._uri = qb::io::uri(path_str);
        } catch (const std::exception& e) {
            ADD_FAILURE() << "Failed to parse URI for request: " << path_str << " - " << e.what();
            req._uri = qb::io::uri("/__test_uri_parse_failure__");
        }
        _router->route(_session_ptr, std::move(req)); 
        _task_executor.processAllTasks(); 
    }
    
    bool was_task_executed(const std::string& name) const {
        if (!_session_ptr) return false;
        return std::find(_session_ptr->_executed_task_names.begin(), 
                         _session_ptr->_executed_task_names.end(), 
                         name) != _session_ptr->_executed_task_names.end();
    }

    size_t count_task_executions(const std::string& name) const {
        if (!_session_ptr) return 0;
        return std::count(_session_ptr->_executed_task_names.begin(),
                          _session_ptr->_executed_task_names.end(),
                          name);
    }
};

// --- Test Cases ---

TEST_F(RouterErrorHandlingTest, ErrorInHandlerTriggersErrorChain) {
    auto erroring_route_lambda = [this](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) {
        _session_ptr->record_task_execution("ErroringRouteLambda");
        _task_executor.addTask([ctx](){ 
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });
    };

    auto error_chain_task = std::make_shared<NormalCompletingTask>(
        "ErrorHandlerInChain", _session_ptr, _task_executor, 
        HTTP_STATUS_SERVICE_UNAVAILABLE, "Handled by error chain", true 
    );

    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> error_chain_list;
    error_chain_list.push_back(error_chain_task);
    _router->set_error_task_chain(std::move(error_chain_list));
    
    _router->get("/path_to_error", erroring_route_lambda);
    _router->compile();

    make_request(HTTP_GET, "/path_to_error");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("ErroringRouteLambda"));
    EXPECT_TRUE(was_task_executed("ErrorHandlerInChain"));
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);
    EXPECT_EQ(_session_ptr->_response_received.body().as<std::string>(), "Handled by error chain");
    EXPECT_EQ(_session_ptr->_last_error_handler_name_executed, "ErrorHandlerInChain");
}


TEST_F(RouterErrorHandlingTest, ExceptionInHandlerTriggersErrorChain) {
    auto exception_throwing_task_for_route = std::make_shared<ExceptionThrowingTask>(
        "RouteExceptionThrower", _session_ptr, _task_executor
    );
    
     _router->get("/exception_path", exception_throwing_task_for_route);


    auto error_chain_handler_task = std::make_shared<NormalCompletingTask>(
        "ExceptionHandlerInChain", _session_ptr, _task_executor, 
        HTTP_STATUS_INTERNAL_SERVER_ERROR, "Handled by error chain (exception)", true
    );

    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> error_chain_list;
    error_chain_list.push_back(error_chain_handler_task);
    _router->set_error_task_chain(std::move(error_chain_list));
    
    _router->compile();

    make_request(HTTP_GET, "/exception_path");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("RouteExceptionThrower")); 
    EXPECT_TRUE(was_task_executed("ExceptionHandlerInChain"));
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_session_ptr->_response_received.body().as<std::string>(), "Handled by error chain (exception)");
    EXPECT_EQ(_session_ptr->_last_error_handler_name_executed, "ExceptionHandlerInChain");
}


TEST_F(RouterErrorHandlingTest, ErrorInMiddlewareTriggersErrorChain) {
    auto normal_handler_task = std::make_shared<NormalCompletingTask>(
        "NormalHandlerAfterMiddleware", _session_ptr, _task_executor, HTTP_STATUS_OK, "OK from normal handler"
    );

    auto erroring_middleware_impl = std::make_shared<ErrorSignalingTask>(
        "ErrorSignalingMiddlewareItself", _session_ptr, _task_executor
    );

    qb::http::MiddlewareHandlerFn<MockErrorHandlingSession> erroring_mw_fn = 
        [this, erroring_middleware_impl](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx, std::function<void()> /*next_fn*/) {
        this->_task_executor.addTask([ctx, erroring_middleware_impl](){
             erroring_middleware_impl->execute(ctx);
        });
    };
    auto erroring_functional_middleware = std::make_shared<qb::http::FunctionalMiddleware<MockErrorHandlingSession>>(erroring_mw_fn, "ErroringFunctionalMiddleware");

    auto error_chain_handler = std::make_shared<NormalCompletingTask>(
        "MiddlewareErrorChainHandler", _session_ptr, _task_executor, 
        HTTP_STATUS_INTERNAL_SERVER_ERROR, "Handled by error chain (middleware error)", true
    );

    // Create the global middleware task that will also be part of the error chain
    auto global_erroring_middleware_task = std::make_shared<qb::http::MiddlewareTask<MockErrorHandlingSession>>(
        erroring_functional_middleware, // The IMiddleware instance
        erroring_functional_middleware->name() // Use its own name
    );

    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> error_chain_list;
    // Explicitly prepend the global middleware that is expected to error again
    error_chain_list.push_back(global_erroring_middleware_task); 
    error_chain_list.push_back(error_chain_handler); // This handler should now NOT run
    _router->set_error_task_chain(std::move(error_chain_list));

    _router->use(erroring_functional_middleware); // Still add it as global middleware for the normal path
    _router->get("/mw_error_path", normal_handler_task); 
    
    _router->compile();

    make_request(HTTP_GET, "/mw_error_path");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("ErrorSignalingMiddlewareItself")); 
    EXPECT_EQ(count_task_executions("ErrorSignalingMiddlewareItself"), 2);
    EXPECT_FALSE(was_task_executed("NormalHandlerAfterMiddleware")); 
    EXPECT_FALSE(was_task_executed("MiddlewareErrorChainHandler"));
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(_session_ptr->_last_error_handler_name_executed.empty());
}


TEST_F(RouterErrorHandlingTest, GlobalMiddlewarePrependedToErrorChain) {
    std::shared_ptr<qb::http::FunctionalMiddleware<MockErrorHandlingSession>> global_functional_middleware;
    qb::http::MiddlewareHandlerFn<MockErrorHandlingSession> global_mw_fn =
        [this, &global_functional_middleware](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx, std::function<void()> next) {
        // Capture the name from the FunctionalMiddleware instance if needed, or use a fixed name
        std::string mw_name = global_functional_middleware ? global_functional_middleware->name() : "GlobalErrorTestMiddleware";
        _session_ptr->record_task_execution(mw_name); // Use the dynamic or fixed name
        ctx->response().add_header("X-Global-ErrorTest-MW", "Processed");
        _task_executor.addTask([ctx, next](){
            next();
        });
    };
    global_functional_middleware = std::make_shared<qb::http::FunctionalMiddleware<MockErrorHandlingSession>>(global_mw_fn, "GlobalErrorTestMiddleware");
    _router->use(global_functional_middleware); 

    auto error_trigger_lambda = [this](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) {
        _session_ptr->record_task_execution("ErrorTriggerRouteLambda");
        _task_executor.addTask([ctx](){
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });
    };

    auto custom_error_chain_handler = std::make_shared<NormalCompletingTask>(
        "CustomErrorChainHandler", _session_ptr, _task_executor, 
        HTTP_STATUS_CONFLICT, "Custom error handled after global MW", true
    );

    // Explicitly create the global middleware task to add to the error chain
    auto global_mw_task_for_error_chain = std::make_shared<qb::http::MiddlewareTask<MockErrorHandlingSession>>(
        global_functional_middleware, 
        global_functional_middleware->name()
    );

    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> error_chain_list;
    error_chain_list.push_back(global_mw_task_for_error_chain); // Explicitly prepend
    error_chain_list.push_back(custom_error_chain_handler);
    _router->set_error_task_chain(std::move(error_chain_list));
    
    _router->get("/global_error_trigger_path", error_trigger_lambda);
    _router->compile();

    make_request(HTTP_GET, "/global_error_trigger_path");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("ErrorTriggerRouteLambda"));
    
    EXPECT_EQ(count_task_executions("GlobalErrorTestMiddleware"), 2); 
    EXPECT_TRUE(was_task_executed("CustomErrorChainHandler"));
    
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_CONFLICT);
    EXPECT_EQ(_session_ptr->_response_received.body().as<std::string>(), "Custom error handled after global MW");
    EXPECT_EQ(_session_ptr->_last_error_handler_name_executed, "CustomErrorChainHandler");
    EXPECT_EQ(_session_ptr->_response_received.header("X-Global-ErrorTest-MW"), "Processed")
        << "Global middleware header should be present from error chain execution.";
}


TEST_F(RouterErrorHandlingTest, ErrorChainNotSetDefaultsToFinalization) {
    
    _router->get("/error_path_no_chain_set", [this](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) {
        _session_ptr->record_task_execution("ErrorNoChainHandlerLambda");
        _task_executor.addTask([ctx](){\
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });
    });
    _router->compile();

    make_request(HTTP_GET, "/error_path_no_chain_set");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("ErrorNoChainHandlerLambda"));
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR); 
    EXPECT_TRUE(_session_ptr->_last_error_handler_name_executed.empty()) << "No error handler should have been marked as run.";
}


TEST_F(RouterErrorHandlingTest, EmptyErrorChainDefaultsToFinalization) {
    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> empty_error_chain_list;
    _router->set_error_task_chain(std::move(empty_error_chain_list)); 
    
    _router->get("/error_path_empty_chain", [this](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) {
        _session_ptr->record_task_execution("ErrorEmptyChainHandlerLambda");
        _task_executor.addTask([ctx](){\
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });
    });
    _router->compile();

    make_request(HTTP_GET, "/error_path_empty_chain");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("ErrorEmptyChainHandlerLambda"));
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(_session_ptr->_last_error_handler_name_executed.empty());
}


TEST_F(RouterErrorHandlingTest, ErrorInErrorChainHandlerItselfFinalizes) {
    auto initial_error_trigger_task = std::make_shared<ErrorSignalingTask>(
        "InitialErrorTrigger", _session_ptr, _task_executor
    );
    
    auto error_chain_task_that_also_errors = std::make_shared<ErrorSignalingTask>(
        "ErrorChainErrorSignaler", _session_ptr, _task_executor
    );

    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> error_chain_list;
    error_chain_list.push_back(error_chain_task_that_also_errors);
    _router->set_error_task_chain(std::move(error_chain_list));
    
    _router->get("/error_in_error_chain_path", initial_error_trigger_task); 
    _router->compile();

    make_request(HTTP_GET, "/error_in_error_chain_path");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("InitialErrorTrigger"));
    EXPECT_TRUE(was_task_executed("ErrorChainErrorSignaler")); 
    
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(_session_ptr->_last_error_handler_name_executed.empty());
}

TEST_F(RouterErrorHandlingTest, ExceptionInMiddlewareTriggersErrorChain) {
    auto normal_handler_task_after_mw = std::make_shared<NormalCompletingTask>(
        "NormalHandlerAfterThrowingMiddleware", _session_ptr, _task_executor, HTTP_STATUS_OK, "OK from normal handler"
    );

    // Middleware that will throw an exception
    qb::http::MiddlewareHandlerFn<MockErrorHandlingSession> throwing_mw_fn =
        [this](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx, std::function<void()> /*next_fn*/) {
        _session_ptr->record_task_execution("ThrowingMiddlewareLambda");
        // No need to add to _task_executor, FunctionalMiddleware's handle calls this directly.
        // The MiddlewareTask wrapper around FunctionalMiddleware will catch the exception.
        throw std::runtime_error("Exception from middleware lambda");
    };
    auto throwing_functional_middleware = std::make_shared<qb::http::FunctionalMiddleware<MockErrorHandlingSession>>(
        throwing_mw_fn, "ThrowingFunctionalMiddleware"
    );

    auto error_chain_handler_for_mw_exception = std::make_shared<NormalCompletingTask>(
        "MiddlewareExceptionChainHandler", _session_ptr, _task_executor,
        HTTP_STATUS_BAD_GATEWAY, "Handled by error chain (middleware exception)", true
    );

    // Create the global middleware task that will also be part of the error chain
    auto global_throwing_middleware_task = std::make_shared<qb::http::MiddlewareTask<MockErrorHandlingSession>>(
        throwing_functional_middleware, // The IMiddleware instance
        throwing_functional_middleware->name() // Use its own name
    );

    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> error_chain_list_for_mw_ex;
    // Explicitly prepend the global middleware that is expected to throw again
    error_chain_list_for_mw_ex.push_back(global_throwing_middleware_task); 
    error_chain_list_for_mw_ex.push_back(error_chain_handler_for_mw_exception); // This handler should now NOT run
    _router->set_error_task_chain(std::move(error_chain_list_for_mw_ex));

    _router->use(throwing_functional_middleware); // Still add it as global for the normal path
    _router->get("/mw_exception_path", normal_handler_task_after_mw);

    _router->compile();

    make_request(HTTP_GET, "/mw_exception_path");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("ThrowingMiddlewareLambda"));
    EXPECT_EQ(count_task_executions("ThrowingMiddlewareLambda"), 2); 
    EXPECT_FALSE(was_task_executed("NormalHandlerAfterThrowingMiddleware")); 
    EXPECT_FALSE(was_task_executed("MiddlewareExceptionChainHandler"));
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR); 
    EXPECT_TRUE(_session_ptr->_last_error_handler_name_executed.empty());
}

TEST_F(RouterErrorHandlingTest, ExceptionInErrorChainHandlerFinalizes) {
    auto initial_error_trigger_task = std::make_shared<ErrorSignalingTask>(
        "InitialErrorTriggerForExceptionInErrorChain", _session_ptr, _task_executor
    );

    // This task, when part of an error chain, will throw an exception.
    auto error_chain_task_that_throws_exception = std::make_shared<ExceptionThrowingTask>(
        "ErrorChainExceptionThrower", _session_ptr, _task_executor, "Exception from error chain task"
    );

    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> error_chain_list;
    error_chain_list.push_back(error_chain_task_that_throws_exception);
    _router->set_error_task_chain(std::move(error_chain_list));

    _router->get("/path_error_in_error_chain_exception", initial_error_trigger_task);
    _router->compile();

    make_request(HTTP_GET, "/path_error_in_error_chain_exception");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("InitialErrorTriggerForExceptionInErrorChain"));
    EXPECT_TRUE(was_task_executed("ErrorChainExceptionThrower"));

    // Expect a default 500 error because the error chain itself failed by throwing an exception.
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(_session_ptr->_last_error_handler_name_executed.empty()) 
        << "No error handler should have successfully completed and set its name.";
}

TEST_F(RouterErrorHandlingTest, CancellationDuringNormalProcessingTriggersFinalization) {
    // Middleware that will call cancel
    qb::http::MiddlewareHandlerFn<MockErrorHandlingSession> cancelling_mw_fn =
        [this](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx, std::function<void()> /*next_fn*/) {
        _session_ptr->record_task_execution("CancellingMiddlewareLambda");
        _task_executor.addTask([ctx](){
            ctx->cancel(); // Trigger cancellation
        });
        // Middleware doesn't call next() after queuing cancel
    };
    auto cancelling_middleware = std::make_shared<qb::http::FunctionalMiddleware<MockErrorHandlingSession>>(
        cancelling_mw_fn, "CancellingMiddleware"
    );

    auto route_handler_after_cancelling_mw = std::make_shared<NormalCompletingTask>(
        "HandlerAfterCancellingMiddleware", _session_ptr, _task_executor
    );

    // Set up an error chain just to ensure it's NOT called by cancellation
    auto error_chain_task_for_cancel_test = std::make_shared<NormalCompletingTask>(
        "ErrorChainShouldNotRunOnCancel", _session_ptr, _task_executor, HTTP_STATUS_NOT_IMPLEMENTED, "Error chain run on cancel!"
    );
    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> error_chain_list;
    error_chain_list.push_back(error_chain_task_for_cancel_test);
    _router->set_error_task_chain(std::move(error_chain_list));

    _router->use(cancelling_middleware); // Apply middleware globally for this test setup
    _router->get("/path_will_be_cancelled", route_handler_after_cancelling_mw);

    _router->compile();

    make_request(HTTP_GET, "/path_will_be_cancelled");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("CancellingMiddlewareLambda"));
    EXPECT_FALSE(was_task_executed("HandlerAfterCancellingMiddleware")); // This handler should not run
    EXPECT_FALSE(was_task_executed("ErrorChainShouldNotRunOnCancel"));
    
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);
}

TEST_F(RouterErrorHandlingTest, CancellationDuringErrorChainProcessingFinalizes) {
    auto initial_error_trigger_for_cancel_in_error_chain = std::make_shared<ErrorSignalingTask>(
        "InitialErrorForCancelInErrorChain", _session_ptr, _task_executor
    );

    auto error_chain_cancelling_task = std::make_shared<GenericLambdaTask>(
        "ErrorChainCancellingTask", _session_ptr, _task_executor,
        [](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx, TaskExecutor& /*executor*/) {
            // This task is part of the error chain and will call cancel.
            ctx->session()->record_task_execution("ErrorChainCancellingTask_LambdaPart"); // Record explicit execution of this part
            ctx->cancel();
        }
    );

    auto error_chain_subsequent_task_after_cancel = std::make_shared<NormalCompletingTask>(
        "ErrorChainSubsequentTaskAfterCancel", _session_ptr, _task_executor,
        HTTP_STATUS_NOT_IMPLEMENTED, "Error chain subsequent task ran after cancel!"
    );

    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> error_chain_list;
    error_chain_list.push_back(error_chain_cancelling_task);
    error_chain_list.push_back(error_chain_subsequent_task_after_cancel);
    _router->set_error_task_chain(std::move(error_chain_list));

    _router->get("/path_for_cancel_in_error_chain", initial_error_trigger_for_cancel_in_error_chain);
    _router->compile();

    make_request(HTTP_GET, "/path_for_cancel_in_error_chain");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("InitialErrorForCancelInErrorChain"));
    EXPECT_TRUE(was_task_executed("ErrorChainCancellingTask")); // The GenericLambdaTask itself
    EXPECT_TRUE(was_task_executed("ErrorChainCancellingTask_LambdaPart")); // The logic inside GenericLambdaTask
    EXPECT_FALSE(was_task_executed("ErrorChainSubsequentTaskAfterCancel"));

    // Context::cancel currently sets 503.
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);
    EXPECT_TRUE(_session_ptr->_last_error_handler_name_executed.empty()) 
        << "No error handler should have fully completed if cancellation happened.";
}

TEST_F(RouterErrorHandlingTest, ErrorInNotFoundHandlerResultsInInternalServerError) {
    // No routes defined that will match "/unhandled_path"

    qb::http::RouteHandlerFn<MockErrorHandlingSession> erroring_not_found_fn = 
        [this](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) {
        _session_ptr->record_task_execution("ErroringNotFoundLambda");
        _task_executor.addTask([ctx]() {
            ctx->complete(qb::http::AsyncTaskResult::FATAL_SPECIAL_HANDLER_ERROR);
        });
    };
    _router->set_not_found_handler(erroring_not_found_fn);

    // Optional: Set a main error chain to ensure it's NOT called.
    auto main_error_handler_should_not_run = std::make_shared<NormalCompletingTask>(
        "MainErrorHandlerShouldNotRun", _session_ptr, _task_executor, 
        HTTP_STATUS_NOT_IMPLEMENTED, "Main error handler ran for not_found error!", true
    );
    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> main_error_chain_list;
    main_error_chain_list.push_back(main_error_handler_should_not_run);
    _router->set_error_task_chain(std::move(main_error_chain_list));

    _router->compile();
    make_request(HTTP_GET, "/unhandled_path_for_erroring_not_found");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("ErroringNotFoundLambda"));
    EXPECT_FALSE(was_task_executed("MainErrorHandlerShouldNotRun"))
        << "The main error handler should not be executed when the 'not found' handler itself errors.";
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR)
        << "Expected 500 when 'not found' handler errors.";
    EXPECT_TRUE(_session_ptr->_last_error_handler_name_executed.empty())
        << "No specific error handler from the main chain should have completed when 'not found' handler errors.";
}

TEST_F(RouterErrorHandlingTest, GlobalMiddlewareErrorPreventsNotFoundHandlerExecution) {
    qb::http::MiddlewareHandlerFn<MockErrorHandlingSession> erroring_global_mw_fn =
        [this](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx, std::function<void()> /*next*/) {
        _session_ptr->record_task_execution("ErroringGlobalMiddleware");
        _task_executor.addTask([ctx]() {
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });
    };
    auto erroring_global_middleware = std::make_shared<qb::http::FunctionalMiddleware<MockErrorHandlingSession>>(
        erroring_global_mw_fn, "ErroringGlobalMiddleware"
    );
    _router->use(erroring_global_middleware);

    qb::http::RouteHandlerFn<MockErrorHandlingSession> not_found_fn_should_not_run =
        [this](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) {
        _session_ptr->record_task_execution("NotFoundHandlerShouldNotRunLambda");
        ctx->response().status_code = HTTP_STATUS_NOT_FOUND;
        ctx->response().body() = "Not found handler ran despite global MW error!";
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    };
    _router->set_not_found_handler(not_found_fn_should_not_run);

    auto main_error_handler_should_run = std::make_shared<NormalCompletingTask>(
        "MainErrorHandlerForGlobalMwError", _session_ptr, _task_executor, 
        HTTP_STATUS_BAD_GATEWAY, "Main error handler for global MW error", true
    );
    
    // Create an IAsyncTask wrapper for the global middleware to add it to the error chain
    auto erroring_global_middleware_task_for_error_chain = std::make_shared<qb::http::MiddlewareTask<MockErrorHandlingSession>>(
        erroring_global_middleware, // The IMiddleware instance
        erroring_global_middleware->name()
    );

    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> main_error_chain_list;
    // Explicitly prepend the global middleware that is expected to error again in the main error chain
    main_error_chain_list.push_back(erroring_global_middleware_task_for_error_chain); 
    main_error_chain_list.push_back(main_error_handler_should_run); // This handler should now NOT run
    _router->set_error_task_chain(std::move(main_error_chain_list));

    _router->compile();
    make_request(HTTP_GET, "/unhandled_path_for_global_mw_error");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("ErroringGlobalMiddleware"));
    EXPECT_EQ(count_task_executions("ErroringGlobalMiddleware"), 2) 
        << "ErroringGlobalMiddleware should run once in normal chain, once in error chain before erroring again.";
    EXPECT_FALSE(was_task_executed("NotFoundHandlerShouldNotRunLambda"))
        << "The 'not found' handler should not run if a global middleware errors first.";
    EXPECT_FALSE(was_task_executed("MainErrorHandlerForGlobalMwError"))
        << "MainErrorHandlerForGlobalMwError should not run if prepended ErroringGlobalMiddleware errors in the error chain.";
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR)
        << "Expected 500 when the error chain itself fails due to an erroring global middleware.";
    EXPECT_TRUE(_session_ptr->_last_error_handler_name_executed.empty())
        << "No specific error handler should have completed if the error chain itself failed.";
}

TEST_F(RouterErrorHandlingTest, ExceptionInNotFoundHandlerTriggersMainErrorChain) {
    qb::http::RouteHandlerFn<MockErrorHandlingSession> exception_throwing_not_found_fn = 
        [this](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) {
        _session_ptr->record_task_execution("ExceptionThrowingNotFoundLambda");
        // This lambda will throw, simulating an uncaught exception in a not_found handler.
        // The RouteLambdaTask wrapper is expected to catch this and call ctx->complete(ERROR).
        throw std::runtime_error("Exception from not_found_handler lambda");
    };
    _router->set_not_found_handler(exception_throwing_not_found_fn);

    auto main_error_handler = std::make_shared<NormalCompletingTask>(
        "MainErrorHandlerForExceptionInNotFound", _session_ptr, _task_executor, 
        HTTP_STATUS_BAD_GATEWAY, "Handled by main error chain (exception in not_found)", true
    );
    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> main_error_chain_list;
    main_error_chain_list.push_back(main_error_handler);
    _router->set_error_task_chain(std::move(main_error_chain_list));

    _router->compile();
    make_request(HTTP_GET, "/unhandled_path_for_exception_in_not_found");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("ExceptionThrowingNotFoundLambda"));
    EXPECT_TRUE(was_task_executed("MainErrorHandlerForExceptionInNotFound"))
        << "The main error handler should execute when an exception occurs in the 'not found' handler.";
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_BAD_GATEWAY);
    EXPECT_EQ(_session_ptr->_response_received.body().as<std::string>(), "Handled by main error chain (exception in not_found)");
    EXPECT_EQ(_session_ptr->_last_error_handler_name_executed, "MainErrorHandlerForExceptionInNotFound");
}

TEST_F(RouterErrorHandlingTest, FatalErrorInMainErrorChainIsStillFatal) {
    auto initial_error_trigger = std::make_shared<ErrorSignalingTask>(
        "InitialErrorForFatalInErrorChain", _session_ptr, _task_executor
    );

    auto fatal_error_chain_task = std::make_shared<FatalSignalingTask>(
        "FatalSignalingErrorChainTask", _session_ptr, _task_executor
    );
    
    auto subsequent_error_chain_task_should_not_run = std::make_shared<NormalCompletingTask>(
        "SubsequentErrorHandlerShouldNotRun", _session_ptr, _task_executor,
        HTTP_STATUS_NOT_IMPLEMENTED, "Subsequent error handler ran after fatal!", true
    );

    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> error_chain_list;
    error_chain_list.push_back(fatal_error_chain_task);
    error_chain_list.push_back(subsequent_error_chain_task_should_not_run);
    _router->set_error_task_chain(std::move(error_chain_list));

    _router->get("/path_for_fatal_in_error_chain", initial_error_trigger);
    _router->compile();

    make_request(HTTP_GET, "/path_for_fatal_in_error_chain");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("InitialErrorForFatalInErrorChain"));
    EXPECT_TRUE(was_task_executed("FatalSignalingErrorChainTask"));
    EXPECT_FALSE(was_task_executed("SubsequentErrorHandlerShouldNotRun"));
    
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(_session_ptr->_last_error_handler_name_executed.empty())
        << "No error handler should have completed normally if a fatal error occurred in the chain.";
}

TEST_F(RouterErrorHandlingTest, CancellationFromNotFoundHandlerFinalizes) {
    qb::http::RouteHandlerFn<MockErrorHandlingSession> cancelling_not_found_fn =
        [this](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) {
        _session_ptr->record_task_execution("CancellingNotFoundLambda");
        _task_executor.addTask([ctx]() {
            ctx->cancel();
        });
    };
    _router->set_not_found_handler(cancelling_not_found_fn);

    // Add a subsequent task in a hypothetical "not found compiled chain" to ensure it doesn't run.
    // In reality, the set_not_found_handler wraps the lambda, and cancellation should stop further tasks
    // in that implicit chain. This is more for conceptual validation.
    // For this test, the cancellation happens within the lambda itself, so no subsequent "not found tasks" would be relevant.

    auto main_error_handler_should_not_run = std::make_shared<NormalCompletingTask>(
        "MainErrorChainShouldNotRunOnNotFoundCancel", _session_ptr, _task_executor,
        HTTP_STATUS_NOT_IMPLEMENTED, "Main error handler ran for not_found cancellation!", true
    );
    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> main_error_chain_list;
    main_error_chain_list.push_back(main_error_handler_should_not_run);
    _router->set_error_task_chain(std::move(main_error_chain_list));

    _router->compile();
    make_request(HTTP_GET, "/unhandled_path_for_not_found_cancel");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("CancellingNotFoundLambda"));
    EXPECT_FALSE(was_task_executed("MainErrorChainShouldNotRunOnNotFoundCancel"));
    
    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);
    EXPECT_TRUE(_session_ptr->_last_error_handler_name_executed.empty());
}

TEST_F(RouterErrorHandlingTest, CancellationByGlobalMiddlewareDuringNotFoundProcessingFinalizes) {
    // Global middleware that cancels
    qb::http::MiddlewareHandlerFn<MockErrorHandlingSession> cancelling_global_mw_fn =
        [this](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx, std::function<void()> /*next*/) {
        _session_ptr->record_task_execution("CancellingGlobalMiddlewareForNotFound");
        _task_executor.addTask([ctx]() {
            ctx->cancel();
        });
        // Does not call next()
    };
    auto cancelling_global_middleware = std::make_shared<qb::http::FunctionalMiddleware<MockErrorHandlingSession>>(
        cancelling_global_mw_fn, "CancellingGlobalMiddlewareForNotFound"
    );
    _router->use(cancelling_global_middleware);

    // A "not found" handler that should NOT run
    qb::http::RouteHandlerFn<MockErrorHandlingSession> not_found_fn_should_not_run =
        [this](std::shared_ptr<qb::http::Context<MockErrorHandlingSession>> ctx) {
        _session_ptr->record_task_execution("NotFoundHandlerShouldNotRunAfterGlobalCancel");
        ctx->response().status_code = HTTP_STATUS_NOT_FOUND;
        ctx->response().body() = "Not found handler ran despite global MW cancel!";
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    };
    _router->set_not_found_handler(not_found_fn_should_not_run);

    // A main error chain that should NOT run
    auto main_error_handler_should_not_run = std::make_shared<NormalCompletingTask>(
        "MainErrorChainShouldNotRunOnGlobalNotFoundCancel", _session_ptr, _task_executor,
        HTTP_STATUS_NOT_IMPLEMENTED, "Main error handler ran for global not_found cancellation!", true
    );
    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession>>> main_error_chain_list;
    main_error_chain_list.push_back(main_error_handler_should_not_run);
    _router->set_error_task_chain(std::move(main_error_chain_list));

    _router->compile();
    make_request(HTTP_GET, "/unhandled_path_for_global_mw_not_found_cancel");

    EXPECT_TRUE(_session_ptr->_finalized_cb_called);
    EXPECT_TRUE(was_task_executed("CancellingGlobalMiddlewareForNotFound"));
    EXPECT_FALSE(was_task_executed("NotFoundHandlerShouldNotRunAfterGlobalCancel"));
    EXPECT_FALSE(was_task_executed("MainErrorChainShouldNotRunOnGlobalNotFoundCancel"));

    EXPECT_EQ(_session_ptr->_response_received.status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);
    EXPECT_TRUE(_session_ptr->_last_error_handler_name_executed.empty());
}

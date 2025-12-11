#include <gtest/gtest.h>
#include "../http.h" // Provides qb::http::Router, Request, Response, Context, RouteGroup, etc.
#include <qb/uuid.h>    // For qb::uuid and qb::generate_random_uuid
#include <memory>
#include <string>
#include <vector>
#include <functional> // For std::function
#include <iostream>   // For potential debugging, can be removed later

// --- Helper Classes for RouteGroup Tests ---

// Simple Task Executor (can be refactored into a common test utility later)
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

// Mock Session for RouteGroup Tests
struct MockRouteGroupSession {
    qb::http::Response _response;
    qb::uuid _session_id = qb::generate_random_uuid();
    std::string _trace_log; // For logging execution order
    qb::http::PathParameters _captured_params;
    bool _handler_executed_flag = false;

    qb::http::Response &get_response_ref() { return _response; }

    MockRouteGroupSession &operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    [[nodiscard]] const qb::uuid &id() const { return _session_id; }

    void reset() {
        _response = qb::http::Response();
        _trace_log.clear();
        _captured_params = qb::http::PathParameters();
        _handler_executed_flag = false;
    }

    void trace(const std::string &point) {
        if (!_trace_log.empty()) {
            _trace_log += ";";
        }
        _trace_log += point;
    }

    const std::string &get_trace() const {
        return _trace_log;
    }
};

// Test Fixture for RouteGroup Tests
class RouterRouteGroupTest : public ::testing::Test {
protected:
    std::shared_ptr<MockRouteGroupSession> _mock_session;
    qb::http::Router<MockRouteGroupSession> _router;
    TaskExecutor _task_executor; // For testing async operations

    void SetUp() override {
        _mock_session = std::make_shared<MockRouteGroupSession>();
    }

    qb::http::Request create_request(qb::http::method method_val, const std::string &target_path) {
        qb::http::Request req;
        req.method() = method_val;
        try {
            req.uri() = qb::io::uri(target_path);
        } catch (const std::exception &e) {
            ADD_FAILURE() << "Failed to parse URI: " << target_path << " - " << e.what();
            // Set a default valid URI to prevent crashes in Request object if parsing fails
            req.uri() = qb::io::uri("/__invalid_uri_due_to_parse_failure__");
        }
        req.major_version = 1;
        req.minor_version = 1;
        return req;
    }

    // Helper to make a simple synchronous handler for testing
    qb::http::RouteHandlerFn<MockRouteGroupSession> make_simple_handler(
        const std::string &id, qb::http::status status = qb::http::status::OK,
        const std::string &body_prefix = "Handler response: ") {
        return [id, status, body_prefix](std::shared_ptr<qb::http::Context<MockRouteGroupSession> > ctx) {
            if (ctx->session()) {
                ctx->session()->trace(id);
                ctx->session()->_handler_executed_flag = true;
            }
            ctx->response().status() = status;
            ctx->response().body() = body_prefix + id;
            ctx->complete();
        };
    }
};

// --- Helper Middleware for RouteGroup Tests ---

class TestRouteGroupSyncMiddleware : public qb::http::IMiddleware<MockRouteGroupSession> {
public:
    TestRouteGroupSyncMiddleware(std::string id, std::string header_to_set = "", std::string value_to_set = "")
        : _id(std::move(id)), _header_to_set(std::move(header_to_set)), _value_to_set(std::move(value_to_set)) {
    }

    void process(std::shared_ptr<qb::http::Context<MockRouteGroupSession> > ctx) override {
        if (ctx->session()) {
            ctx->session()->trace(_id);
        }
        if (!_header_to_set.empty()) {
            ctx->request().set_header(_header_to_set, _value_to_set); // Modify request for downstream
            ctx->response().set_header(_header_to_set, _value_to_set); // Or response for upstream/final
        }
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }

    std::string name() const override { return _id; }

    void cancel() override {
        if (_id.find("cancel") != std::string::npos) {
            /* simple check for test */
        }
    }

private:
    std::string _id;
    std::string _header_to_set;
    std::string _value_to_set;
};

class TestRouteGroupAsyncMiddleware : public qb::http::IMiddleware<MockRouteGroupSession> {
public:
    TestRouteGroupAsyncMiddleware(std::string id, TaskExecutor *executor, std::string header_to_set = "",
                                  std::string value_to_set = "")
        : _id(std::move(id)), _executor(executor), _header_to_set(std::move(header_to_set)),
          _value_to_set(std::move(value_to_set)) {
        if (!_executor) throw std::runtime_error("TaskExecutor cannot be null for Async Middleware");
    }

    void process(std::shared_ptr<qb::http::Context<MockRouteGroupSession> > ctx) override {
        if (ctx->session()) {
            ctx->session()->trace(_id + "_HANDLE_CALLED");
        }
        auto shared_ctx = ctx;
        _executor->addTask([shared_ctx, this]() {
            if (shared_ctx->session()) {
                shared_ctx->session()->trace(_id + "_TASK_EXECUTED");
            }
            if (!this->_header_to_set.empty()) {
                shared_ctx->request().set_header(this->_header_to_set, this->_value_to_set);
                shared_ctx->response().set_header(this->_header_to_set, this->_value_to_set);
            }
            shared_ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
        });
    }

    std::string name() const override { return _id; }

    void cancel() override {
    }

private:
    std::string _id;
    TaskExecutor *_executor;
    std::string _header_to_set;
    std::string _value_to_set;
};

class TestRouteGroupShortCircuitMiddleware : public qb::http::IMiddleware<MockRouteGroupSession> {
public:
    TestRouteGroupShortCircuitMiddleware(std::string id, qb::http::status status_code, std::string body)
        : _id(std::move(id)), _status_code(status_code), _body(std::move(body)) {
    }

    void process(std::shared_ptr<qb::http::Context<MockRouteGroupSession> > ctx) override {
        if (ctx->session()) ctx->session()->trace(_id);
        ctx->response().status() = _status_code;
        ctx->response().body() = _body;
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE); // Short-circuit
    }

    std::string name() const override { return _id; }

    void cancel() override {
    }

private:
    std::string _id;
    qb::http::status _status_code;
    std::string _body;
};

class TestRouteGroupErrorMiddleware : public qb::http::IMiddleware<MockRouteGroupSession> {
public:
    TestRouteGroupErrorMiddleware(std::string id,
                                  qb::http::status status_to_set_before_error = qb::http::status::SERVICE_UNAVAILABLE,
                                  std::string body_prefix = "Error from mw: ")
        : _id(std::move(id)), _status_to_set_before_error(status_to_set_before_error),
          _body_prefix(std::move(body_prefix)) {
    }

    void process(std::shared_ptr<qb::http::Context<MockRouteGroupSession> > ctx) override {
        if (ctx->session()) ctx->session()->trace(_id);
        ctx->response().status() = _status_to_set_before_error;
        ctx->response().body() = _body_prefix + _id;
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
    }

    std::string name() const override { return _id; }

    void cancel() override {
    }

private:
    std::string _id;
    qb::http::status _status_to_set_before_error;
    std::string _body_prefix;
};

// --- Helper Controller for RouteGroup Tests ---
class TestSimpleController : public qb::http::Controller<MockRouteGroupSession> {
public:
    TestSimpleController() : qb::http::Controller<MockRouteGroupSession>() {
        // Call default Controller ctor
        // The actual base path segment will be set by RouteGroup::controller using set_base_path_segment.
        // This controller defines routes relative to that future base path.
        initialize_routes();
    }

    void initialize_routes() override {
        // This middleware will be prepended to controller's own task chain for its routes
        this->use(std::make_shared<TestRouteGroupSyncMiddleware>("ctrl_sync_mw"));

        this->add_controller_route("/hello", qb::http::method::GET,
                                   [](std::shared_ptr<qb::http::Context<MockRouteGroupSession> > ctx) {
                                       if (ctx->session()) {
                                           ctx->session()->trace("ctrl_hello_handler");
                                       }
                                       ctx->response().status() = qb::http::status::OK;
                                       ctx->response().body() = "Hello from controller in group";
                                       ctx->complete();
                                   });

        this->add_controller_route("/world", qb::http::method::GET,
                                   [](std::shared_ptr<qb::http::Context<MockRouteGroupSession> > ctx) {
                                       if (ctx->session()) {
                                           ctx->session()->trace("ctrl_world_handler");
                                       }
                                       ctx->response().status() = qb::http::status::OK;
                                       ctx->response().body() = "World from controller in group";
                                       ctx->complete();
                                   });
    }

    // Correctly override get_node_name from IHandlerNode
    std::string get_node_name() const override { return "TestSimpleController"; }
};

// --- Helper Custom Route for RouteGroup Tests ---
class TestCustomRoute : public qb::http::ICustomRoute<MockRouteGroupSession> {
public:
    TestCustomRoute(std::string id, bool signal_error = false, qb::http::status status_code = qb::http::status::OK,
                    std::string body_content = "Custom Route Body")
        : _id(std::move(id)), _signal_error(signal_error), _status_code(status_code),
          _body_content(std::move(body_content)) {
    }

    void process(std::shared_ptr<qb::http::Context<MockRouteGroupSession> > ctx) override {
        if (ctx->session()) {
            ctx->session()->trace(_id);
        }
        if (_signal_error) {
            ctx->response().status() = qb::http::status::EXPECTATION_FAILED; // Some status before error
            ctx->response().body() = "Custom route " + _id + " signaling error";
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        } else {
            ctx->response().status() = _status_code;
            ctx->response().body() = _body_content;
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
        }
    }

    std::string name() const override { return "TestCustomRoute_" + _id; }

    void cancel() override {
        /* No-op for this simple test version */
    }

private:
    std::string _id;
    bool _signal_error;
    qb::http::status _status_code;
    std::string _body_content;
};

// --- Basic RouteGroup Tests ---

TEST_F(RouterRouteGroupTest, MountRouteGroupAndCallRoute) {
    auto group = _router.group("/api");
    group->get("/users", make_simple_handler("api_users_handler"));

    _router.compile();

    auto request = create_request(HTTP_GET, "/api/users");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Handler response: api_users_handler");
    EXPECT_EQ(_mock_session->get_trace(), "api_users_handler");
    EXPECT_TRUE(_mock_session->_handler_executed_flag);
}

TEST_F(RouterRouteGroupTest, NestedRouteGroup) {
    auto api_group = _router.group("/api");
    auto v1_group = api_group->group("/v1");
    v1_group->get("/status", make_simple_handler("api_v1_status_handler"));

    _router.compile();

    auto request = create_request(HTTP_GET, "/api/v1/status");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Handler response: api_v1_status_handler");
    EXPECT_EQ(_mock_session->get_trace(), "api_v1_status_handler");
    EXPECT_TRUE(_mock_session->_handler_executed_flag);
}

TEST_F(RouterRouteGroupTest, RouteGroupWithPathParameters) {
    auto items_group = _router.group("/items");
    items_group->get("/:item_id/details",
                     [](std::shared_ptr<qb::http::Context<MockRouteGroupSession> > ctx) {
                         if (ctx->session()) {
                             ctx->session()->trace("item_details_handler");
                             ctx->session()->_handler_executed_flag = true;
                             ctx->session()->_captured_params = ctx->path_parameters();
                         }
                         // Explicitly construct std::string from std::string_view
                         std::string item_id_str(ctx->path_parameters().get("item_id").value_or("NOT_FOUND"));
                         ctx->response().status() = qb::http::status::OK;
                         ctx->response().body() = "Item: " + item_id_str;
                         ctx->complete();
                     }
    );

    _router.compile();

    auto request = create_request(HTTP_GET, "/items/abc789/details");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Item: abc789");
    EXPECT_EQ(_mock_session->get_trace(), "item_details_handler");
    EXPECT_TRUE(_mock_session->_handler_executed_flag);
    ASSERT_TRUE(_mock_session->_captured_params.get("item_id").has_value());
    EXPECT_EQ(_mock_session->_captured_params.get("item_id").value(), "abc789");
}

// --- RouteGroup Middleware Tests ---

TEST_F(RouterRouteGroupTest, RouteGroupWithSyncMiddleware) {
    auto api_group = _router.group("/api");
    api_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("group_sync_mw"));
    api_group->get("/data", make_simple_handler("api_data_handler"));

    _router.compile();

    auto request = create_request(HTTP_GET, "/api/data");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Handler response: api_data_handler");
    EXPECT_EQ(_mock_session->get_trace(), "group_sync_mw;api_data_handler");
    EXPECT_TRUE(_mock_session->_handler_executed_flag);
}

TEST_F(RouterRouteGroupTest, RouteGroupWithAsyncMiddleware) {
    auto api_group = _router.group("/api");
    api_group->use(std::make_shared<TestRouteGroupAsyncMiddleware>("group_async_mw", &_task_executor));
    api_group->get("/data", make_simple_handler("api_data_handler"));

    _router.compile();

    auto request = create_request(HTTP_GET, "/api/data");
    _router.route(_mock_session, std::move(request));

    // Middleware handle called, task queued
    EXPECT_EQ(_mock_session->get_trace(), "group_async_mw_HANDLE_CALLED");
    ASSERT_FALSE(_mock_session->_handler_executed_flag);
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 1);

    _task_executor.processAllTasks(); // Process middleware task

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Handler response: api_data_handler");
    EXPECT_EQ(_mock_session->get_trace(), "group_async_mw_HANDLE_CALLED;group_async_mw_TASK_EXECUTED;api_data_handler");
    EXPECT_TRUE(_mock_session->_handler_executed_flag);
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 0);
}

TEST_F(RouterRouteGroupTest, MiddlewareInParentAndNestedGroup) {
    auto api_group = _router.group("/api");
    api_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("api_mw"));

    auto v1_group = api_group->group("/v1");
    v1_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("v1_mw"));
    v1_group->get("/status", make_simple_handler("status_handler"));

    _router.compile();

    auto request = create_request(HTTP_GET, "/api/v1/status");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Handler response: status_handler");
    EXPECT_EQ(_mock_session->get_trace(), "api_mw;v1_mw;status_handler");
    EXPECT_TRUE(_mock_session->_handler_executed_flag);
}

TEST_F(RouterRouteGroupTest, GlobalAndGroupMiddlewareInteraction) {
    _router.use(std::make_shared<TestRouteGroupSyncMiddleware>("global_mw"));

    auto api_group = _router.group("/api");
    api_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("api_mw"));
    api_group->get("/data", make_simple_handler("data_handler"));

    _router.compile();

    auto request = create_request(HTTP_GET, "/api/data");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Handler response: data_handler");
    EXPECT_EQ(_mock_session->get_trace(), "global_mw;api_mw;data_handler");
    EXPECT_TRUE(_mock_session->_handler_executed_flag);
}

TEST_F(RouterRouteGroupTest, GroupMiddlewareShortCircuit) {
    auto api_group = _router.group("/api");
    api_group->use(
        std::make_shared<TestRouteGroupShortCircuitMiddleware>("short_circuit_mw", HTTP_STATUS_ACCEPTED,
                                                               "Short-circuited!"));
    api_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("after_short_mw"));
    api_group->get("/data", make_simple_handler("api_data_handler"));

    _router.compile();

    auto request = create_request(HTTP_GET, "/api/data");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_ACCEPTED);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Short-circuited!");
    EXPECT_EQ(_mock_session->get_trace(), "short_circuit_mw");
    ASSERT_FALSE(_mock_session->_handler_executed_flag); // Handler should not have run
}

TEST_F(RouterRouteGroupTest, GroupMiddlewareSignalsError) {
    auto api_group = _router.group("/api");
    api_group->use(std::make_shared<TestRouteGroupErrorMiddleware>("error_signal_mw"));
    api_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("after_error_mw"));
    api_group->get("/data", make_simple_handler("api_data_handler"));

    // No specific router-level error handler set for this test, expect default 500
    _router.compile();

    auto request = create_request(HTTP_GET, "/api/data");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
    // Body might be the one set by TestRouteGroupErrorMiddleware or a generic one from RouterCore
    // For now, just check trace and that handler didn't run.
    EXPECT_EQ(_mock_session->get_trace(), "error_signal_mw");
    ASSERT_FALSE(_mock_session->_handler_executed_flag); // Handler should not have run
}

TEST_F(RouterRouteGroupTest, ErrorInRouteHandlerWithinGroup) {
    auto api_group = _router.group("/api");
    api_group->get("/error_route",
                   [](std::shared_ptr<qb::http::Context<MockRouteGroupSession> > ctx) {
                       if (ctx->session()) {
                           ctx->session()->trace("error_handler_in_group");
                       }
                       ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                       ctx->response().body() = "Error in handler within group";
                       ctx->complete(qb::http::AsyncTaskResult::ERROR);
                   }
    );
    api_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("group_mw_before_error_route"));

    _router.compile();

    auto request = create_request(HTTP_GET, "/api/error_route");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_mock_session->get_trace(), "group_mw_before_error_route;error_handler_in_group");
}

// --- Advanced RouteGroup Tests ---

TEST_F(RouterRouteGroupTest, MultipleGroupsAtSameLevel) {
    auto api_group = _router.group("/api");
    api_group->get("/users", make_simple_handler("api_users_handler"));

    auto admin_group = _router.group("/admin");
    admin_group->get("/settings", make_simple_handler("admin_settings_handler"));

    _router.compile();

    // Test API group
    _mock_session->reset();
    auto request_api = create_request(HTTP_GET, "/api/users");
    _router.route(_mock_session, std::move(request_api));
    _task_executor.processAllTasks();
    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Handler response: api_users_handler");
    EXPECT_EQ(_mock_session->get_trace(), "api_users_handler");

    // Test Admin group
    _mock_session->reset();
    auto request_admin = create_request(HTTP_GET, "/admin/settings");
    _router.route(_mock_session, std::move(request_admin));
    _task_executor.processAllTasks();
    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Handler response: admin_settings_handler");
    EXPECT_EQ(_mock_session->get_trace(), "admin_settings_handler");
}

TEST_F(RouterRouteGroupTest, MiddlewareOrderInGroup) {
    auto group = _router.group("/test");
    group->use(std::make_shared<TestRouteGroupSyncMiddleware>("mw1"));
    group->use(std::make_shared<TestRouteGroupSyncMiddleware>("mw2"));
    group->get("/resource", make_simple_handler("resource_handler"));

    _router.compile();

    auto request = create_request(HTTP_GET, "/test/resource");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->get_trace(), "mw1;mw2;resource_handler");
}

TEST_F(RouterRouteGroupTest, EmptyRouteGroupNotFound) {
    auto empty_group = _router.group("/empty");
    // Add middleware to ensure it runs even if no route is matched in group
    empty_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("empty_group_mw"));

    _router.compile();

    auto request = create_request(HTTP_GET, "/empty/nonexistent");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);
    // Default 404 handler in RouterCore does not trace. Check body instead.
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "404 Not Found (Default)");
    EXPECT_EQ(_mock_session->get_trace(), ""); // Trace should be empty if no other middleware ran and traced
}

TEST_F(RouterRouteGroupTest, ControllerMountedInRouteGroup) {
    _router.use(std::make_shared<TestRouteGroupSyncMiddleware>("global_mw"));

    auto api_group = _router.group("/api");
    api_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("api_group_mw"));

    // Use RouteGroup::controller<ControllerType>(mount_path_prefix)
    auto controller = api_group->template controller<TestSimpleController>("/v1/service/ctrl");

    _router.compile();

    auto request = create_request(HTTP_GET, "/api/v1/service/ctrl/hello");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Hello from controller in group");
    EXPECT_EQ(_mock_session->get_trace(), "global_mw;api_group_mw;ctrl_sync_mw;ctrl_hello_handler");
}

TEST_F(RouterRouteGroupTest, ControllerMountedInRouteGroupWithEmptyControllerPrefix) {
    _router.use(std::make_shared<TestRouteGroupSyncMiddleware>("global_mw"));

    auto api_group = _router.group("/api");
    api_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("api_group_mw"));

    // Mount controller at /api/ctrl (since TestSimpleController defines routes like /hello, /world relative to its base)
    // The RouteGroup::controller method sets the base_path_segment of the controller to "ctrl"
    auto controller_direct = api_group->template controller<TestSimpleController>("ctrl");

    _router.compile();

    auto request = create_request(HTTP_GET, "/api/ctrl/world");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "World from controller in group");
    EXPECT_EQ(_mock_session->get_trace(), "global_mw;api_group_mw;ctrl_sync_mw;ctrl_world_handler");
}

TEST_F(RouterRouteGroupTest, PathParameterPropagationFromGroupToRoute) {
    auto tenant_group = _router.group("/tenant/:tenant_id");
    tenant_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("tenant_mw"));
    // The handler for route /user/:user_id/profile within group /tenant/:tenant_id
    // Path parameters from both group and route should be available.
    // The final path pattern registered would be something like /tenant/:tenant_id/user/:user_id/profile
    tenant_group->get("/user/:user_id/profile",
                      [](std::shared_ptr<qb::http::Context<MockRouteGroupSession> > ctx) {
                          if (ctx->session()) {
                              ctx->session()->trace("profile_handler");
                              ctx->session()->_captured_params = ctx->path_parameters();
                          }
                          std::string tenant_id = std::string(ctx->path_parameters().get("tenant_id").value_or("N/A"));
                          std::string user_id = std::string(ctx->path_parameters().get("user_id").value_or("N/A"));
                          ctx->response().status() = qb::http::status::OK;
                          ctx->response().body() = "Tenant: " + tenant_id + ", User: " + user_id;
                          ctx->complete();
                      }
    );

    _router.compile();

    auto request = create_request(HTTP_GET, "/tenant/acme_corp/user/usr_123/profile");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Tenant: acme_corp, User: usr_123");
    EXPECT_EQ(_mock_session->get_trace(), "tenant_mw;profile_handler");
    ASSERT_TRUE(_mock_session->_captured_params.get("tenant_id").has_value());
    EXPECT_EQ(_mock_session->_captured_params.get("tenant_id").value(), "acme_corp");
    ASSERT_TRUE(_mock_session->_captured_params.get("user_id").has_value());
    EXPECT_EQ(_mock_session->_captured_params.get("user_id").value(), "usr_123");
}

TEST_F(RouterRouteGroupTest, NotFoundWithinGroupUsesRouterNotFoundHandler) {
    // Use set_not_found_handler with a single lambda
    _router.set_not_found_handler(
        [](std::shared_ptr<qb::http::Context<MockRouteGroupSession> > ctx) {
            // Explicitly type ctx
            if (ctx->session()) {
                // Check session existence
                ctx->session()->trace("CUSTOM_404_HANDLER");
            }
            ctx->response().status() = qb::http::status::NOT_FOUND;
            ctx->response().body() = "Custom Page Not Found From Router";
            ctx->complete();
        }
    );

    auto api_group = _router.group("/api");
    api_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("api_group_mw_for_404"));
    api_group->get("/actual_route", make_simple_handler("actual_route_handler"));
    // An actual route to ensure group is processed

    // Add the global middleware that is expected in the trace
    _router.use(std::make_shared<TestRouteGroupSyncMiddleware>("global_router_mw_for_404_test"));

    _router.compile();

    _mock_session->reset(); // Reset session for a clean trace for this specific test action
    auto request = create_request(HTTP_GET, "/api/this_route_does_not_exist");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Custom Page Not Found From Router");
    // Expected: global_router_mw_for_404_test (router global) -> CUSTOM_404_HANDLER (router's 404)
    // Group middleware api_group_mw_for_404 does not run if the 404 happens after matching the group's prefix.
    EXPECT_EQ(_mock_session->get_trace(), "global_router_mw_for_404_test;CUSTOM_404_HANDLER");
}

TEST_F(RouterRouteGroupTest, ErrorInGroupMiddlewareUsesRouterErrorHandler) {
    auto global_mw_for_error_test_instance = std::make_shared<TestRouteGroupSyncMiddleware>("global_mw_for_error_test");
    _router.use(global_mw_for_error_test_instance);

    // Create an IAsyncTask wrapper for the global middleware to add it to the error chain
    auto global_mw_task_for_error_chain = std::make_shared<qb::http::MiddlewareTask<MockRouteGroupSession> >(
        global_mw_for_error_test_instance, // The IMiddleware instance
        global_mw_for_error_test_instance->name()
    );

    std::vector<std::shared_ptr<qb::http::IAsyncTask<MockRouteGroupSession> > > error_chain_tasks;
    error_chain_tasks.push_back(global_mw_task_for_error_chain); // Explicitly prepend
    error_chain_tasks.push_back(
        std::make_shared<qb::http::MiddlewareTask<MockRouteGroupSession> >(
            std::make_shared<TestRouteGroupSyncMiddleware>("custom_error_mw")
        )
    );
    error_chain_tasks.push_back(
        std::make_shared<qb::http::RouteLambdaTask<MockRouteGroupSession> >(
            [](std::shared_ptr<qb::http::Context<MockRouteGroupSession> > ctx) {
                // Explicitly type ctx
                if (ctx->session()) {
                    // Check session existence
                    ctx->session()->trace("CUSTOM_500_HANDLER");
                }
                ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                ctx->response().body() = "Custom Internal Error From Router";
                ctx->complete();
            }
        )
    );
    _router.set_error_task_chain(std::move(error_chain_tasks));

    auto api_group = _router.group("/api");
    api_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("api_group_mw_before_error"));
    api_group->use(std::make_shared<TestRouteGroupErrorMiddleware>("group_error_trigger_mw")); // This one signals error
    api_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("api_group_mw_after_error")); // Should not run
    api_group->get("/some_route", make_simple_handler("some_route_handler")); // Should not run

    _router.compile();

    auto request = create_request(HTTP_GET, "/api/some_route");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Custom Internal Error From Router");
    // Expected trace: global_mw_for_error_test (router global) -> api_group_mw_before_error (group) -> group_error_trigger_mw (group, signals error)
    // Then error chain: global_mw_for_error_test (router global, re-applied for error chain) -> custom_error_mw -> CUSTOM_500_HANDLER
    // The RouterCore prepends global _router_ tasks also to the error chain.
    EXPECT_EQ(_mock_session->get_trace(),
              "global_mw_for_error_test;api_group_mw_before_error;group_error_trigger_mw;global_mw_for_error_test;custom_error_mw;CUSTOM_500_HANDLER");
}

// --- Additional RouteGroup Tests ---

TEST_F(RouterRouteGroupTest, DeeplyNestedGroupMiddleware) {
    _router.use(std::make_shared<TestRouteGroupSyncMiddleware>("global_mw"));

    auto l1_group = _router.group("/level1");
    l1_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("l1_mw"));

    auto l2_group = l1_group->group("/level2");
    l2_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("l2_mw"));

    auto l3_group = l2_group->group("/level3");
    l3_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("l3_mw"));
    l3_group->get("/endpoint", make_simple_handler("final_handler"));

    _router.compile();
    _mock_session->reset();
    auto request = create_request(HTTP_GET, "/level1/level2/level3/endpoint");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->get_trace(), "global_mw;l1_mw;l2_mw;l3_mw;final_handler");
}

TEST_F(RouterRouteGroupTest, CustomRouteInGroupWithGroupMiddleware) {
    auto api_group = _router.group("/api");
    api_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("group_mw_for_custom_route"));

    // Add using shared_ptr instance
    api_group->get("/custom1", std::make_shared<TestCustomRoute>("custom_route_hdlr1"));
    // Add using templated version (if RouteGroup supports it like Router, otherwise adapt)
    // For now, assuming RouteGroup has similar templated add_custom_route or get<CustomType>
    // Let's use the add_custom_route from RouteGroup for clarity, if available, or the get(path, shared_ptr)
    // Re-checking route_group.h, it has `get(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route)`
    // and `add_custom_route<CustomRouteType>(...)` and `get<CustomRouteType>(...)`.
    // Let's use the specific templated `get` for variety if it implies construction.
    api_group->template get<TestCustomRoute>("/custom2", "custom_route_hdlr2_constructed");


    _router.compile();

    // Test /custom1
    _mock_session->reset();
    auto request1 = create_request(HTTP_GET, "/api/custom1");
    _router.route(_mock_session, std::move(request1));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Custom Route Body");
    EXPECT_EQ(_mock_session->get_trace(), "group_mw_for_custom_route;custom_route_hdlr1");

    // Test /custom2
    _mock_session->reset();
    auto request2 = create_request(HTTP_GET, "/api/custom2");
    _router.route(_mock_session, std::move(request2));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Custom Route Body");
    // Default body from TestCustomRoute constructor
    EXPECT_EQ(_mock_session->get_trace(), "group_mw_for_custom_route;custom_route_hdlr2_constructed");
}

TEST_F(RouterRouteGroupTest, GroupAsEndpoint) {
    auto base_group = _router.group("/base");
    base_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("base_group_mw"));
    base_group->get("", make_simple_handler("base_as_endpoint")); // Route for "/base" itself

    _router.compile();
    _mock_session->reset();
    auto request = create_request(HTTP_GET, "/base");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Handler response: base_as_endpoint");
    EXPECT_EQ(_mock_session->get_trace(), "base_group_mw;base_as_endpoint");
}

TEST_F(RouterRouteGroupTest, GroupAsEndpointWithSlash) {
    auto base_group = _router.group("/base"); // Group prefix is /base
    base_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("base_slash_group_mw"));
    // Route for "/base/" (path segment "/" relative to group prefix "/base")
    base_group->get("/", make_simple_handler("base_slash_as_endpoint"));

    _router.compile();
    _mock_session->reset();
    auto request = create_request(HTTP_GET, "/base/");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Handler response: base_slash_as_endpoint");
    EXPECT_EQ(_mock_session->get_trace(), "base_slash_group_mw;base_slash_as_endpoint");
}

TEST_F(RouterRouteGroupTest, ErrorInCustomRouteInGroup) {
    auto global_mw_instance = std::make_shared<TestRouteGroupSyncMiddleware>("global_mw_for_custom_error");
    _router.use(global_mw_instance);

    // Create an IAsyncTask wrapper for the global middleware
    auto global_mw_task_for_error_chain = std::make_shared<qb::http::MiddlewareTask<MockRouteGroupSession> >(
        global_mw_instance,
        global_mw_instance->name()
    );

    std::vector<std::shared_ptr<qb::http::IAsyncTask<MockRouteGroupSession> > > error_chain_tasks;
    error_chain_tasks.push_back(global_mw_task_for_error_chain); // Explicitly prepend
    error_chain_tasks.push_back(
        std::make_shared<qb::http::MiddlewareTask<MockRouteGroupSession> >(
            std::make_shared<TestRouteGroupSyncMiddleware>("router_error_chain_mw")
        )
    );
    error_chain_tasks.push_back(
        std::make_shared<qb::http::RouteLambdaTask<MockRouteGroupSession> >(
            [](std::shared_ptr<qb::http::Context<MockRouteGroupSession> > ctx) {
                if (ctx->session()) ctx->session()->trace("ROUTER_CUSTOM_500_HANDLER");
                ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                ctx->response().body() = "Router Custom 500 from ErrorInCustomRouteInGroup";
                ctx->complete();
            }, "RouterCustom500Lambda")
    );
    _router.set_error_task_chain(std::move(error_chain_tasks));

    auto error_group = _router.group("/error_group");
    error_group->use(std::make_shared<TestRouteGroupSyncMiddleware>("error_group_mw"));
    error_group->get("/trigger", std::make_shared<TestCustomRoute>("custom_error_trigger", true /* signal error */));

    _router.compile();
    _mock_session->reset();
    auto request = create_request(HTTP_GET, "/error_group/trigger");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Router Custom 500 from ErrorInCustomRouteInGroup");
    // Trace: global -> group_mw -> custom_route (signals error) -> global (for error chain) -> router_error_chain_mw -> ROUTER_CUSTOM_500_HANDLER
    EXPECT_EQ(_mock_session->get_trace(),
              "global_mw_for_custom_error;error_group_mw;custom_error_trigger;global_mw_for_custom_error;router_error_chain_mw;ROUTER_CUSTOM_500_HANDLER");
}

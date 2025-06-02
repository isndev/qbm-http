#include <gtest/gtest.h>
#include "../routing.h" // Main include for all routing components
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <iostream> // For potential debug prints during development

// --- Mock Session ---
struct MockApiSession {
    qb::http::Response _response;

    MockApiSession &operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }
};

// --- Helper Handler Lambda ---
qb::http::RouteHandlerFn<MockApiSession> simple_api_lambda_handler(const std::string &id) {
    return [id](std::shared_ptr<qb::http::Context<MockApiSession> > ctx) {
        ctx->response().body() = "Lambda " + id;
        ctx->complete();
    };
}

// --- Helper ICustomRoute ---
class SimpleApiCustomRoute : public qb::http::ICustomRoute<MockApiSession> {
public:
    std::string _id;

    SimpleApiCustomRoute(std::string id, const std::string & /*arg2_placeholder*/ = "") : _id(std::move(id)) {
    }

    void process(std::shared_ptr<qb::http::Context<MockApiSession> > ctx) override {
        ctx->response().body() = "CustomRoute " + _id;
        ctx->complete();
    }

    std::string name() const override { return "SimpleApiCustomRoute_" + _id; }

    void cancel() override {
    }
};

// --- Helper IMiddleware ---
class SimpleApiMiddleware : public qb::http::IMiddleware<MockApiSession> {
public:
    std::string _id;

    SimpleApiMiddleware(std::string id, const std::string & /*arg2_placeholder*/ = "") : _id(std::move(id)) {
    }

    void process(std::shared_ptr<qb::http::Context<MockApiSession> > ctx) override {
        ctx->request().set_header("X-Middleware-" + _id, "applied");
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }

    std::string name() const override { return "SimpleApiMiddleware_" + _id; }

    void cancel() override {
    }
};

// --- Helper Controller for API Tests ---
class ApiTestController : public qb::http::Controller<MockApiSession> {
public:
    ApiTestController() = default;

    // Constructor to satisfy controller<C>(path, args...) if args are provided
    ApiTestController(const std::string & /*name_placeholder*/) {
    }

    void initialize_routes() override {
        // Lambda Handlers
        this->get("/lambda_get", simple_api_lambda_handler("CtrlGetLambda"));
        this->post("/lambda_post", simple_api_lambda_handler("CtrlPostLambda"));
        this->put("/lambda_put", simple_api_lambda_handler("CtrlPutLambda"));
        this->del("/lambda_delete", simple_api_lambda_handler("CtrlDeleteLambda"));
        this->patch("/lambda_patch", simple_api_lambda_handler("CtrlPatchLambda"));
        this->options("/lambda_options", simple_api_lambda_handler("CtrlOptionsLambda"));
        this->head("/lambda_head", simple_api_lambda_handler("CtrlHeadLambda"));

        // Typed Custom Routes
        this->get<SimpleApiCustomRoute>("/custom_get_typed", "CtrlGetCustomTyped", "arg2");
        this->post<SimpleApiCustomRoute>("/custom_post_typed", "CtrlPostCustomTyped", "arg2");
        this->put<SimpleApiCustomRoute>("/custom_put_typed", "CtrlPutCustomTyped", "arg2");
        this->del<SimpleApiCustomRoute>("/custom_delete_typed", "CtrlDeleteCustomTyped", "arg2");
        this->patch<SimpleApiCustomRoute>("/custom_patch_typed", "CtrlPatchCustomTyped", "arg2");
        this->options<SimpleApiCustomRoute>("/custom_options_typed", "CtrlOptionsCustomTyped", "arg2");
        this->head<SimpleApiCustomRoute>("/custom_head_typed", "CtrlHeadCustomTyped", "arg2");

        // Shared_ptr Custom Routes
        auto shared_custom_route = std::make_shared<SimpleApiCustomRoute>("CtrlSharedCustom");
        this->get("/custom_shared_get", shared_custom_route);
        this->post("/custom_shared_post", shared_custom_route);
        this->put("/custom_shared_put", shared_custom_route);
        this->del("/custom_shared_delete", shared_custom_route);
        this->patch("/custom_shared_patch", shared_custom_route);
        this->options("/custom_shared_options", shared_custom_route);
        this->head("/custom_shared_head", shared_custom_route);

        // Controller Middleware
        this->use<SimpleApiMiddleware>("CtrlMwTyped", "arg2");
        this->use(std::make_shared<SimpleApiMiddleware>("CtrlMwShared"));
    }

    std::string get_node_name() const override { return "ApiTestController"; }
};


// --- Test Fixture ---
class RouterApiCompilationTest : public ::testing::Test {
protected:
    std::shared_ptr<qb::http::Router<MockApiSession> > _router;

    void SetUp() override {
        _router = std::make_shared<qb::http::Router<MockApiSession> >();
    }
};

TEST_F(RouterApiCompilationTest, AllApisCompile) {
    // --- Router Level API Tests ---
    // Lambda Handlers
    _router->get("/r_lambda_get", simple_api_lambda_handler("RGetLambda"));
    _router->post("/r_lambda_post", simple_api_lambda_handler("RPostLambda"));
    _router->put("/r_lambda_put", simple_api_lambda_handler("RPutLambda"));
    _router->del("/r_lambda_delete", simple_api_lambda_handler("RDeleteLambda"));
    _router->patch("/r_lambda_patch", simple_api_lambda_handler("RPatchLambda"));
    _router->options("/r_lambda_options", simple_api_lambda_handler("ROptionsLambda"));
    _router->head("/r_lambda_head", simple_api_lambda_handler("RHeadLambda"));

    // Typed Custom Routes
    _router->get<SimpleApiCustomRoute>("/r_custom_get_typed", "RGetCustomTyped", "arg2");
    _router->post<SimpleApiCustomRoute>("/r_custom_post_typed", "RPostCustomTyped", "arg2");
    _router->put<SimpleApiCustomRoute>("/r_custom_put_typed", "RPutCustomTyped", "arg2");
    _router->del<SimpleApiCustomRoute>("/r_custom_delete_typed", "RDeleteCustomTyped", "arg2");
    _router->patch<SimpleApiCustomRoute>("/r_custom_patch_typed", "RPatchCustomTyped", "arg2");
    _router->options<SimpleApiCustomRoute>("/r_custom_options_typed", "ROptionsCustomTyped", "arg2");
    _router->head<SimpleApiCustomRoute>("/r_custom_head_typed", "RHeadCustomTyped", "arg2");

    // Shared_ptr Custom Routes
    auto r_shared_custom = std::make_shared<SimpleApiCustomRoute>("RSharedCustom");
    _router->get("/r_custom_shared_get", r_shared_custom);
    _router->post("/r_custom_shared_post", r_shared_custom);
    _router->put("/r_custom_shared_put", r_shared_custom);
    _router->del("/r_custom_shared_delete", r_shared_custom);
    _router->patch("/r_custom_shared_patch", r_shared_custom);
    _router->options("/r_custom_shared_options", r_shared_custom);
    _router->head("/r_custom_shared_head", r_shared_custom);

    // Router Middleware
    _router->use<SimpleApiMiddleware>("RouterMwTyped", "arg2");
    _router->use(std::make_shared<SimpleApiMiddleware>("RouterMwShared"));
    _router->use([](auto ctx, auto next) {
        ctx->request().set_header("X-Router-Func-Mw", "applied");
        next();
    }, "RouterMwFunctional");

    // --- RouteGroup Level API Tests ---
    auto group1 = _router->group("/group1");
    // Lambda Handlers
    group1->get("/g1_lambda_get", simple_api_lambda_handler("G1GetLambda"));
    group1->post("/g1_lambda_post", simple_api_lambda_handler("G1PostLambda"));
    group1->put("/g1_lambda_put", simple_api_lambda_handler("G1PutLambda"));
    group1->del("/g1_lambda_delete", simple_api_lambda_handler("G1DeleteLambda"));
    group1->patch("/g1_lambda_patch", simple_api_lambda_handler("G1PatchLambda"));
    group1->options("/g1_lambda_options", simple_api_lambda_handler("G1OptionsLambda"));
    group1->head("/g1_lambda_head", simple_api_lambda_handler("G1HeadLambda"));

    // Typed Custom Routes
    group1->get<SimpleApiCustomRoute>("/g1_custom_get_typed", "G1GetCustomTyped", "arg2");
    group1->post<SimpleApiCustomRoute>("/g1_custom_post_typed", "G1PostCustomTyped", "arg2");
    group1->put<SimpleApiCustomRoute>("/g1_custom_put_typed", "G1PutCustomTyped", "arg2");
    group1->del<SimpleApiCustomRoute>("/g1_custom_delete_typed", "G1DeleteCustomTyped", "arg2");
    group1->patch<SimpleApiCustomRoute>("/g1_custom_patch_typed", "G1PatchCustomTyped", "arg2");
    group1->options<SimpleApiCustomRoute>("/g1_custom_options_typed", "G1OptionsCustomTyped", "arg2");
    group1->head<SimpleApiCustomRoute>("/g1_custom_head_typed", "G1HeadCustomTyped", "arg2");

    // Shared_ptr Custom Routes
    auto g1_shared_custom = std::make_shared<SimpleApiCustomRoute>("G1SharedCustom");
    group1->get("/g1_custom_shared_get", g1_shared_custom);
    group1->post("/g1_custom_shared_post", g1_shared_custom);
    group1->put("/g1_custom_shared_put", g1_shared_custom);
    group1->del("/g1_custom_shared_delete", g1_shared_custom);
    group1->patch("/g1_custom_shared_patch", g1_shared_custom);
    group1->options("/g1_custom_shared_options", g1_shared_custom);
    group1->head("/g1_custom_shared_head", g1_shared_custom);

    // Group Middleware
    group1->use<SimpleApiMiddleware>("Group1MwTyped", "arg2");
    group1->use(std::make_shared<SimpleApiMiddleware>("Group1MwShared"));
    group1->use([](auto ctx, auto next) {
        ctx->request().set_header("X-Group1-Func-Mw", "applied");
        next();
    }, "Group1MwFunctional");

    // Nested Group
    auto group2 = group1->group("/group2");
    group2->get("/hello", simple_api_lambda_handler("Group2GetLambda"));
    group2->use<SimpleApiMiddleware>("Group2MwTyped", "arg2");

    // --- Controller Mounting ---
    auto ctrl1 = _router->controller<ApiTestController>("/controller_api_test");
    auto ctrl2_with_args = _router->controller<ApiTestController>("/controller_api_test_args", "arg_for_ctrl_ctor");
    // ApiTestController's initialize_routes() is tested implicitly when controller is compiled.

    // Nested controller
    auto ctrl_in_group = group1->controller<ApiTestController>("/controller_in_group1");
    auto ctrl_in_group_args = group1->controller<ApiTestController>("/controller_in_group1_args",
                                                                    "arg_for_ctrl_ctor_in_group");

    // Attempt to compile everything
    try {
        _router->compile();
        SUCCEED() << "Router configuration compiled successfully.";
    } catch (const std::exception &e) {
        FAIL() << "Router compilation failed: " << e.what();
    } catch (...) {
        FAIL() << "Router compilation failed with an unknown exception.";
    }
}

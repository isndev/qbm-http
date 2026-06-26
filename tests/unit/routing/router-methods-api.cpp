/**
 * @file qbm/http/tests/unit/routing/router-methods-api.cpp
 * @brief Behavioral matrix for the routing-builder DSL across every scope.
 *
 * Historically this file (`test-router-api.cpp`) was a *compile-guard*: it
 * registered ~70 routes/middleware across every verb × handler-kind × scope
 * (router / group / nested group / controller, lambda / typed-custom-route /
 * shared-custom-route, plus typed/shared/functional middleware) and then
 * asserted nothing but `SUCCEED()` after `compile()`. The combinatorial API
 * surface was guarded against overload-resolution breakage, but no request was
 * ever dispatched, so none of the handler bodies or middleware effects were
 * observed.
 *
 * Per the binding spec (§2 `test-router-api.cpp` → router-methods-api.cpp) the
 * `SUCCEED()` is upgraded into a behavioral matrix: every scope keeps its full
 * registration surface (so the compile-guard value is retained), and on top of
 * that we drive at least one in-memory request per scope through a real
 * `qb::http::Router` and `EXPECT_EQ` the observable @ref qb::http::Response —
 * the body marker each handler writes AND the request headers each middleware
 * injects (echoed back into the response so they are inspectable post-route).
 *
 * Pure logic: no event loop, no socket, no timing. The shared
 * @ref qb::http::test::MockSession captures the finalized response.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <functional>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

#include "../../shared/mock_session.h"

using qb::http::test::create_request;
using Session = qb::http::test::MockSession;

namespace {

// ---------------------------------------------------------------------------
// Handlers / middleware that write distinguishable, assertable markers.
//
// Each handler writes a "Lambda <id>" or "CustomRoute <id>" body AND echoes the
// request headers the upstream middleware injected into the response (prefixed
// X-Echo-) so the middleware effect is observable on the captured response.
// ---------------------------------------------------------------------------

// The set of middleware-injected request-header names we echo back. Echoing is
// done by the handler because middleware mutates the *request*, which is not
// otherwise visible on the finalized response.
inline void
echo_injected_headers(const std::shared_ptr<qb::http::Context<Session>> &ctx) {
    for (const std::string name : {"X-Middleware-RouterMwTyped", "X-Middleware-RouterMwShared", "X-Router-Func-Mw",
                             "X-Middleware-Group1MwTyped", "X-Middleware-Group1MwShared", "X-Group1-Func-Mw",
                             "X-Middleware-Group2MwTyped", "X-Middleware-CtrlMwTyped", "X-Middleware-CtrlMwShared"}) {
        if (ctx->request().has_header(name)) {
            ctx->response().set_header(std::string("X-Echo-") + name, ctx->request().header(name));
        }
    }
}

qb::http::RouteHandlerFn<Session>
lambda_handler(const std::string &id) {
    return [id](std::shared_ptr<qb::http::Context<Session>> ctx) {
        echo_injected_headers(ctx);
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "Lambda " + id;
        ctx->complete();
    };
}

class SimpleCustomRoute : public qb::http::ICustomRoute<Session> {
public:
    explicit SimpleCustomRoute(std::string id, const std::string & /*unused*/ = "")
        : _id(std::move(id)) {}

    void
    process(std::shared_ptr<qb::http::Context<Session>> ctx) override {
        echo_injected_headers(ctx);
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "CustomRoute " + _id;
        ctx->complete();
    }

    [[nodiscard]] std::string
    name() const override {
        return "SimpleCustomRoute_" + _id;
    }

    void
    cancel() override {}

private:
    std::string _id;
};

// Middleware that injects a request header named after its id, then continues.
class HeaderInjectMiddleware : public qb::http::IMiddleware<Session> {
public:
    explicit HeaderInjectMiddleware(std::string id, const std::string & /*unused*/ = "")
        : _id(std::move(id)) {}

    void
    process(std::shared_ptr<qb::http::Context<Session>> ctx) override {
        ctx->request().set_header("X-Middleware-" + _id, "applied");
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }

    [[nodiscard]] std::string
    name() const override {
        return "HeaderInjectMiddleware_" + _id;
    }

    void
    cancel() override {}

private:
    std::string _id;
};

// Controller exercising every verb × handler-kind plus controller-level use<>.
class ApiTestController : public qb::http::Controller<Session> {
public:
    ApiTestController() = default;
    explicit ApiTestController(const std::string & /*ctor-arg*/) {}

    void
    initialize_routes() override {
        // Lambda handlers (one per verb).
        this->get("/lambda_get", lambda_handler("CtrlGetLambda"));
        this->post("/lambda_post", lambda_handler("CtrlPostLambda"));
        this->put("/lambda_put", lambda_handler("CtrlPutLambda"));
        this->del("/lambda_delete", lambda_handler("CtrlDeleteLambda"));
        this->patch("/lambda_patch", lambda_handler("CtrlPatchLambda"));
        this->options("/lambda_options", lambda_handler("CtrlOptionsLambda"));
        this->head("/lambda_head", lambda_handler("CtrlHeadLambda"));

        // Typed custom routes (one per verb).
        this->get<SimpleCustomRoute>("/custom_get_typed", "CtrlGetCustomTyped", "arg2");
        this->post<SimpleCustomRoute>("/custom_post_typed", "CtrlPostCustomTyped", "arg2");
        this->put<SimpleCustomRoute>("/custom_put_typed", "CtrlPutCustomTyped", "arg2");
        this->del<SimpleCustomRoute>("/custom_delete_typed", "CtrlDeleteCustomTyped", "arg2");
        this->patch<SimpleCustomRoute>("/custom_patch_typed", "CtrlPatchCustomTyped", "arg2");
        this->options<SimpleCustomRoute>("/custom_options_typed", "CtrlOptionsCustomTyped", "arg2");
        this->head<SimpleCustomRoute>("/custom_head_typed", "CtrlHeadCustomTyped", "arg2");

        // Shared_ptr custom routes (one shared instance over every verb).
        auto shared_custom = std::make_shared<SimpleCustomRoute>("CtrlSharedCustom");
        this->get("/custom_shared_get", shared_custom);
        this->post("/custom_shared_post", shared_custom);
        this->put("/custom_shared_put", shared_custom);
        this->del("/custom_shared_delete", shared_custom);
        this->patch("/custom_shared_patch", shared_custom);
        this->options("/custom_shared_options", shared_custom);
        this->head("/custom_shared_head", shared_custom);

        // Controller-level middleware (typed + shared).
        this->use<HeaderInjectMiddleware>("CtrlMwTyped", "arg2");
        this->use(std::make_shared<HeaderInjectMiddleware>("CtrlMwShared"));
    }

    [[nodiscard]] std::string
    get_node_name() const override {
        return "ApiTestController";
    }
};

// Registers the full combinatorial API surface (every verb × handler-kind ×
// scope, every middleware kind) into @p router, then compiles. This preserves
// the original file's compile-guard coverage of the builder overloads.
void
register_full_surface(qb::http::Router<Session> &router) {
    // --- Router scope ------------------------------------------------------
    router.get("/r_lambda_get", lambda_handler("RGetLambda"));
    router.post("/r_lambda_post", lambda_handler("RPostLambda"));
    router.put("/r_lambda_put", lambda_handler("RPutLambda"));
    router.del("/r_lambda_delete", lambda_handler("RDeleteLambda"));
    router.patch("/r_lambda_patch", lambda_handler("RPatchLambda"));
    router.options("/r_lambda_options", lambda_handler("ROptionsLambda"));
    router.head("/r_lambda_head", lambda_handler("RHeadLambda"));

    router.get<SimpleCustomRoute>("/r_custom_get_typed", "RGetCustomTyped", "arg2");
    router.post<SimpleCustomRoute>("/r_custom_post_typed", "RPostCustomTyped", "arg2");
    router.put<SimpleCustomRoute>("/r_custom_put_typed", "RPutCustomTyped", "arg2");
    router.del<SimpleCustomRoute>("/r_custom_delete_typed", "RDeleteCustomTyped", "arg2");
    router.patch<SimpleCustomRoute>("/r_custom_patch_typed", "RPatchCustomTyped", "arg2");
    router.options<SimpleCustomRoute>("/r_custom_options_typed", "ROptionsCustomTyped", "arg2");
    router.head<SimpleCustomRoute>("/r_custom_head_typed", "RHeadCustomTyped", "arg2");

    auto r_shared = std::make_shared<SimpleCustomRoute>("RSharedCustom");
    router.get("/r_custom_shared_get", r_shared);
    router.post("/r_custom_shared_post", r_shared);
    router.put("/r_custom_shared_put", r_shared);
    router.del("/r_custom_shared_delete", r_shared);
    router.patch("/r_custom_shared_patch", r_shared);
    router.options("/r_custom_shared_options", r_shared);
    router.head("/r_custom_shared_head", r_shared);

    router.use<HeaderInjectMiddleware>("RouterMwTyped", "arg2");
    router.use(std::make_shared<HeaderInjectMiddleware>("RouterMwShared"));
    router.use(
        [](auto ctx, auto next) {
            ctx->request().set_header("X-Router-Func-Mw", "applied");
            next();
        },
        "RouterMwFunctional");

    // --- Group scope -------------------------------------------------------
    auto group1 = router.group("/group1");
    group1->get("/g1_lambda_get", lambda_handler("G1GetLambda"));
    group1->post("/g1_lambda_post", lambda_handler("G1PostLambda"));
    group1->put("/g1_lambda_put", lambda_handler("G1PutLambda"));
    group1->del("/g1_lambda_delete", lambda_handler("G1DeleteLambda"));
    group1->patch("/g1_lambda_patch", lambda_handler("G1PatchLambda"));
    group1->options("/g1_lambda_options", lambda_handler("G1OptionsLambda"));
    group1->head("/g1_lambda_head", lambda_handler("G1HeadLambda"));

    group1->get<SimpleCustomRoute>("/g1_custom_get_typed", "G1GetCustomTyped", "arg2");
    group1->post<SimpleCustomRoute>("/g1_custom_post_typed", "G1PostCustomTyped", "arg2");
    group1->put<SimpleCustomRoute>("/g1_custom_put_typed", "G1PutCustomTyped", "arg2");
    group1->del<SimpleCustomRoute>("/g1_custom_delete_typed", "G1DeleteCustomTyped", "arg2");
    group1->patch<SimpleCustomRoute>("/g1_custom_patch_typed", "G1PatchCustomTyped", "arg2");
    group1->options<SimpleCustomRoute>("/g1_custom_options_typed", "G1OptionsCustomTyped", "arg2");
    group1->head<SimpleCustomRoute>("/g1_custom_head_typed", "G1HeadCustomTyped", "arg2");

    auto g1_shared = std::make_shared<SimpleCustomRoute>("G1SharedCustom");
    group1->get("/g1_custom_shared_get", g1_shared);
    group1->post("/g1_custom_shared_post", g1_shared);
    group1->put("/g1_custom_shared_put", g1_shared);
    group1->del("/g1_custom_shared_delete", g1_shared);
    group1->patch("/g1_custom_shared_patch", g1_shared);
    group1->options("/g1_custom_shared_options", g1_shared);
    group1->head("/g1_custom_shared_head", g1_shared);

    group1->use<HeaderInjectMiddleware>("Group1MwTyped", "arg2");
    group1->use(std::make_shared<HeaderInjectMiddleware>("Group1MwShared"));
    group1->use(
        [](auto ctx, auto next) {
            ctx->request().set_header("X-Group1-Func-Mw", "applied");
            next();
        },
        "Group1MwFunctional");

    // --- Nested group scope ------------------------------------------------
    auto group2 = group1->group("/group2");
    group2->get("/hello", lambda_handler("Group2GetLambda"));
    group2->use<HeaderInjectMiddleware>("Group2MwTyped", "arg2");

    // --- Controller mounting (with and without ctor arg) -------------------
    (void) router.controller<ApiTestController>("/controller_api_test");
    (void) router.controller<ApiTestController>("/controller_api_test_args", "arg_for_ctrl_ctor");
    (void) group1->controller<ApiTestController>("/controller_in_group1");
    (void) group1->controller<ApiTestController>("/controller_in_group1_args", "arg_for_ctrl_ctor_in_group");

    router.compile();
}

// Drives one request through a freshly-built router and returns the captured
// response via the MockSession.
std::shared_ptr<Session>
drive(qb::http::Router<Session> &router, qb::http::method m, const std::string &path) {
    auto session = std::make_shared<Session>();
    router.route(session, create_request(m, path));
    return session;
}

} // namespace

// ---------------------------------------------------------------------------
// The original compile-guard: registering every overload still compiles and
// compile() does not throw. Retained verbatim in intent.
// ---------------------------------------------------------------------------
TEST(RouterMethodsApi, FullSurfaceCompiles) {
    qb::http::Router<Session> router;
    ASSERT_NO_THROW(register_full_surface(router));
}

// ---------------------------------------------------------------------------
// Router scope: every verb dispatches its lambda handler and the response body
// carries the verb-specific marker.
// ---------------------------------------------------------------------------
TEST(RouterMethodsApi, RouterScopeLambdaVerbMatrix) {
    qb::http::Router<Session> router;
    register_full_surface(router);

    struct Row {
        qb::http::method method;
        std::string      path;
        std::string      expected_body;
    };
    const Row rows[] = {
        {HTTP_GET, "/r_lambda_get", "Lambda RGetLambda"},
        {HTTP_POST, "/r_lambda_post", "Lambda RPostLambda"},
        {HTTP_PUT, "/r_lambda_put", "Lambda RPutLambda"},
        {HTTP_DELETE, "/r_lambda_delete", "Lambda RDeleteLambda"},
        {HTTP_PATCH, "/r_lambda_patch", "Lambda RPatchLambda"},
        {HTTP_OPTIONS, "/r_lambda_options", "Lambda ROptionsLambda"},
    };
    for (const auto &row : rows) {
        auto session = drive(router, row.method, row.path);
        EXPECT_EQ(session->_response.status(), HTTP_STATUS_OK) << row.path;
        EXPECT_EQ(session->_response.body().as<std::string>(), row.expected_body) << row.path;
        // Router-level middleware (all three kinds) ran and was echoed back.
        EXPECT_EQ(session->_response.header("X-Echo-X-Middleware-RouterMwTyped"), "applied") << row.path;
        EXPECT_EQ(session->_response.header("X-Echo-X-Middleware-RouterMwShared"), "applied") << row.path;
        EXPECT_EQ(session->_response.header("X-Echo-X-Router-Func-Mw"), "applied") << row.path;
    }
}

// ---------------------------------------------------------------------------
// Router scope: typed and shared custom routes dispatch and write their marker.
// ---------------------------------------------------------------------------
TEST(RouterMethodsApi, RouterScopeCustomRouteKinds) {
    qb::http::Router<Session> router;
    register_full_surface(router);

    auto typed = drive(router, HTTP_GET, "/r_custom_get_typed");
    EXPECT_EQ(typed->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(typed->_response.body().as<std::string>(), "CustomRoute RGetCustomTyped");

    auto shared = drive(router, HTTP_POST, "/r_custom_shared_post");
    EXPECT_EQ(shared->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(shared->_response.body().as<std::string>(), "CustomRoute RSharedCustom");
    // Router middleware applies to custom routes too.
    EXPECT_EQ(shared->_response.header("X-Echo-X-Router-Func-Mw"), "applied");
}

// ---------------------------------------------------------------------------
// Group scope: the group prefix is applied and the group's own middleware
// chain (typed/shared/functional) runs on top of the router's.
// ---------------------------------------------------------------------------
TEST(RouterMethodsApi, GroupScopeDispatchAndMiddleware) {
    qb::http::Router<Session> router;
    register_full_surface(router);

    auto session = drive(router, HTTP_GET, "/group1/g1_lambda_get");
    EXPECT_EQ(session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(session->_response.body().as<std::string>(), "Lambda G1GetLambda");
    // Both router-level and group-level middleware ran.
    EXPECT_EQ(session->_response.header("X-Echo-X-Router-Func-Mw"), "applied");
    EXPECT_EQ(session->_response.header("X-Echo-X-Middleware-Group1MwTyped"), "applied");
    EXPECT_EQ(session->_response.header("X-Echo-X-Middleware-Group1MwShared"), "applied");
    EXPECT_EQ(session->_response.header("X-Echo-X-Group1-Func-Mw"), "applied");

    // A group custom route under the same prefix.
    auto custom = drive(router, HTTP_PUT, "/group1/g1_custom_shared_put");
    EXPECT_EQ(custom->_response.body().as<std::string>(), "CustomRoute G1SharedCustom");
}

// ---------------------------------------------------------------------------
// Nested group: prefixes compose and the nested group's middleware adds to the
// inherited chain.
// ---------------------------------------------------------------------------
TEST(RouterMethodsApi, NestedGroupScopeDispatch) {
    qb::http::Router<Session> router;
    register_full_surface(router);

    auto session = drive(router, HTTP_GET, "/group1/group2/hello");
    EXPECT_EQ(session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(session->_response.body().as<std::string>(), "Lambda Group2GetLambda");
    // The full nested middleware chain ran: router + group1 + group2.
    EXPECT_EQ(session->_response.header("X-Echo-X-Router-Func-Mw"), "applied");
    EXPECT_EQ(session->_response.header("X-Echo-X-Middleware-Group1MwTyped"), "applied");
    EXPECT_EQ(session->_response.header("X-Echo-X-Middleware-Group2MwTyped"), "applied");
}

// ---------------------------------------------------------------------------
// Controller scope: mounted controller dispatches its own routes under the mount
// prefix and the controller-level use<> middleware runs.
// ---------------------------------------------------------------------------
TEST(RouterMethodsApi, ControllerScopeDispatchAndMiddleware) {
    qb::http::Router<Session> router;
    register_full_surface(router);

    // Lambda route inside the controller, mounted at router scope.
    auto lam = drive(router, HTTP_GET, "/controller_api_test/lambda_get");
    EXPECT_EQ(lam->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(lam->_response.body().as<std::string>(), "Lambda CtrlGetLambda");
    // Controller middleware (typed + shared) ran, as did the router middleware.
    EXPECT_EQ(lam->_response.header("X-Echo-X-Middleware-CtrlMwTyped"), "applied");
    EXPECT_EQ(lam->_response.header("X-Echo-X-Middleware-CtrlMwShared"), "applied");
    EXPECT_EQ(lam->_response.header("X-Echo-X-Router-Func-Mw"), "applied");

    // Typed custom route inside the controller.
    auto cust = drive(router, HTTP_POST, "/controller_api_test/custom_post_typed");
    EXPECT_EQ(cust->_response.body().as<std::string>(), "CustomRoute CtrlPostCustomTyped");

    // The controller mounted with a ctor argument behaves identically.
    auto args = drive(router, HTTP_GET, "/controller_api_test_args/lambda_get");
    EXPECT_EQ(args->_response.body().as<std::string>(), "Lambda CtrlGetLambda");

    // A controller nested inside a group inherits the group prefix + middleware.
    auto nested = drive(router, HTTP_GET, "/group1/controller_in_group1/lambda_get");
    EXPECT_EQ(nested->_response.body().as<std::string>(), "Lambda CtrlGetLambda");
    EXPECT_EQ(nested->_response.header("X-Echo-X-Middleware-Group1MwTyped"), "applied");
    EXPECT_EQ(nested->_response.header("X-Echo-X-Middleware-CtrlMwTyped"), "applied");
}

/**
 * @file qbm/http/tests/unit/routing/routing-compile.cpp
 * @brief Route-pattern ambiguity validation at compile() time and recoverability.
 *
 * One of the four focused unit files carved out of the legacy `test-router.cpp`
 * monolith. Route patterns are validated when @ref qb::http::Router::compile() walks
 * the registered routes into the radix tree (see `routing/radix_tree.h`): a malformed
 * or ambiguous pattern throws `std::invalid_argument`. This file pins those throws and
 * — critically — that the router *recovers*: after a failed compile, a fresh router
 * (the documented reset idiom) compiles and serves valid routes normally.
 *
 * Adopts shared @ref qb::http::test::MockSession / create_request.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include "../http.h"
#include "../../shared/mock_session.h"

using qb::http::test::create_request;
using qb::http::test::MockSession;

namespace {

class RoutingCompileTest : public ::testing::Test {
protected:
    std::shared_ptr<MockSession>  session = std::make_shared<MockSession>();
    qb::http::Router<MockSession> router;

    static void
    noop_handler(std::shared_ptr<qb::http::Context<MockSession>> ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    }
};

// --------------------------------------------------------------------------
// Ambiguity validation
// --------------------------------------------------------------------------

TEST_F(RoutingCompileTest, DuplicateParameterNameThrows) {
    // Two segments capturing the same name (:id/:id) is ambiguous.
    router.get("/test/:id/:id", &RoutingCompileTest::noop_handler);

    EXPECT_THROW(router.compile(), std::invalid_argument);
}

TEST_F(RoutingCompileTest, ConflictingParameterAndWildcardNameThrows) {
    // A parameter and a wildcard sharing one capture name (:name/*name) is ambiguous.
    router.get("/other/:name/*name", &RoutingCompileTest::noop_handler);

    EXPECT_THROW(router.compile(), std::invalid_argument);
}

TEST_F(RoutingCompileTest, UnnamedWildcardThrows) {
    // A wildcard must be named (e.g. *rest); a bare '*' is rejected.
    router.get("/files/*", &RoutingCompileTest::noop_handler);

    EXPECT_THROW(router.compile(), std::invalid_argument);
}

TEST_F(RoutingCompileTest, UnnamedParameterThrows) {
    // A parameter must be named (e.g. :id); a bare ':' is rejected.
    router.get("/users/:/profile", &RoutingCompileTest::noop_handler);

    EXPECT_THROW(router.compile(), std::invalid_argument);
}

TEST_F(RoutingCompileTest, WildcardNotLastSegmentThrows) {
    // A wildcard must be the terminal segment; anything after it is illegal.
    router.get("/files/*rest/more", &RoutingCompileTest::noop_handler);

    EXPECT_THROW(router.compile(), std::invalid_argument);
}

TEST_F(RoutingCompileTest, ConflictingWildcardNamesAtSameLevelThrows) {
    // Two routes whose wildcard captures share a level but use different names
    // (*a vs *b) collide when the second is woven into the tree.
    router.get("/dl/*a", &RoutingCompileTest::noop_handler);
    router.post("/dl/*b", &RoutingCompileTest::noop_handler);

    EXPECT_THROW(router.compile(), std::invalid_argument);
}

TEST_F(RoutingCompileTest, ConflictingParameterNamesAtSameLevelThrows) {
    // Two routes that put a parameter at the same level but name it differently
    // (:x vs :y) are ambiguous — the radix node can hold only one param name.
    router.get("/api/:x/edit", &RoutingCompileTest::noop_handler);
    router.post("/api/:y/view", &RoutingCompileTest::noop_handler);

    EXPECT_THROW(router.compile(), std::invalid_argument);
}

// --------------------------------------------------------------------------
// Duplicate-route registration: last definition wins (not an error)
// --------------------------------------------------------------------------

TEST_F(RoutingCompileTest, DuplicateRouteSamePathMethodCompilesAndLastWins) {
    router.get("/dup", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "first";
        ctx->complete();
    });
    router.get("/dup", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "second";
        ctx->complete();
    });

    ASSERT_NO_THROW(router.compile());

    router.route(session, create_request(qb::http::method::GET, "/dup"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "second");
    EXPECT_EQ(session->response_write_count(), 1u);
}

// --------------------------------------------------------------------------
// Recoverability: a fresh router serves valid routes after a failed compile
// --------------------------------------------------------------------------

TEST_F(RoutingCompileTest, RouterRecoversAfterAmbiguousCompile) {
    router.get("/test/:id/:id", &RoutingCompileTest::noop_handler);
    ASSERT_THROW(router.compile(), std::invalid_argument);

    // Documented reset idiom: re-initialize the router after a throwing compile.
    router = qb::http::Router<MockSession>();
    router.get("/good/route", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "good";
        ctx->complete();
    });

    ASSERT_NO_THROW(router.compile());

    router.route(session, create_request(qb::http::method::GET, "/good/route"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "good");
    EXPECT_EQ(session->response_write_count(), 1u);
}

// --------------------------------------------------------------------------
// Valid complex patterns compile without error
// --------------------------------------------------------------------------

TEST_F(RoutingCompileTest, ValidMixedPatternsCompileCleanly) {
    auto ok = [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    };
    router.get("/", ok);
    router.get("/users/:id", ok);
    router.get("/users/:id/items/:itemId", ok);
    router.get("/static/specific", ok);
    router.get("/static/*rest", ok);

    EXPECT_NO_THROW(router.compile());
}

// --------------------------------------------------------------------------
// Adapter task unit-tests: RouteLambdaTask / CustomRouteAdapterTask / Route
//
// These drive the route.h IAsyncTask adapters DIRECTLY (no router), pinning the
// null-argument guards, the catch(...) / no-context exception-logging arms, the
// custom-route cancel() delegation, and Route::get_node_name(). The catch(...)
// arms (a non-std throw escaping a handler) and the `ctx == nullptr` log arms are
// only reachable by constructing the adapter by hand, so they live here.
// --------------------------------------------------------------------------

namespace {

// A bare context factory mirroring context-slots.cpp: never driven through the
// router, so no finalised-state invariant is tripped by manual completion.
std::shared_ptr<qb::http::Context<MockSession>>
make_bare_ctx(std::shared_ptr<MockSession> sess) {
    return std::make_shared<qb::http::Context<MockSession>>(
        qb::http::Request{}, qb::http::Response{}, sess, [](qb::http::Context<MockSession> &) {},
        std::weak_ptr<qb::http::RouterCore<MockSession>>{});
}

// Minimal ICustomRoute whose process()/cancel() behaviour is configurable.
class ConfigurableCustomRoute : public qb::http::ICustomRoute<MockSession> {
public:
    enum class Mode { CompleteOk, ThrowStd, ThrowNonStd };

    explicit ConfigurableCustomRoute(Mode mode, std::string name = "ConfigurableCustomRoute")
        : _mode(mode)
        , _name(std::move(name)) {}

    void
    process(std::shared_ptr<qb::http::Context<MockSession>> ctx) override {
        switch (_mode) {
            case Mode::CompleteOk:
                ctx->response().status() = qb::http::status::OK;
                ctx->complete();
                break;
            case Mode::ThrowStd:
                throw std::runtime_error("custom-route std throw");
            case Mode::ThrowNonStd:
                throw 7777; // non-std → drives catch(...) arm
        }
    }

    void
    cancel() override {
        ++cancel_calls;
        if (_cancel_throws) {
            throw std::runtime_error("custom-route cancel throw");
        }
    }

    [[nodiscard]] std::string
    name() const override {
        return _name;
    }

    void
    set_cancel_throws(bool v) {
        _cancel_throws = v;
    }

    int cancel_calls = 0;

private:
    Mode        _mode;
    std::string _name;
    bool        _cancel_throws = false;
};

} // namespace

// --- Null-argument constructor guards --------------------------------------

TEST(RouteAdapters, RouteLambdaTaskNullHandlerThrows) {
    qb::http::RouteHandlerFn<MockSession> null_fn;
    EXPECT_THROW((qb::http::RouteLambdaTask<MockSession>(null_fn)), std::invalid_argument);
}

TEST(RouteAdapters, CustomRouteAdapterTaskNullPointerThrows) {
    std::shared_ptr<qb::http::ICustomRoute<MockSession>> null_ptr;
    EXPECT_THROW((qb::http::CustomRouteAdapterTask<MockSession>(null_ptr)), std::invalid_argument);
}

TEST(RouteAdapters, RouteCtorRejectsNullLambda) {
    qb::http::RouteHandlerFn<MockSession> null_fn;
    EXPECT_THROW((qb::http::Route<MockSession>("/p", qb::http::method::GET, null_fn)), std::invalid_argument);
}

TEST(RouteAdapters, RouteCtorRejectsNullCustomRoute) {
    std::shared_ptr<qb::http::ICustomRoute<MockSession>> null_ptr;
    EXPECT_THROW((qb::http::Route<MockSession>("/p", qb::http::method::GET, null_ptr)), std::invalid_argument);
}

// --- get_node_name() formats method + handler name -------------------------

TEST(RouteAdapters, RouteNodeNameForLambda) {
    qb::http::Route<MockSession> route("seg", qb::http::method::GET, [](auto ctx) { ctx->complete(); });
    const std::string            name = route.get_node_name();
    EXPECT_NE(name.find("Route:"), std::string::npos);
    EXPECT_NE(name.find("Lambda@seg"), std::string::npos);
    EXPECT_EQ(route.get_http_method(), qb::http::method::GET);
}

TEST(RouteAdapters, RouteNodeNameForCustomRoute) {
    auto custom = std::make_shared<ConfigurableCustomRoute>(ConfigurableCustomRoute::Mode::CompleteOk, "MyCustom");
    qb::http::Route<MockSession> route("seg", qb::http::method::POST, custom);
    EXPECT_NE(route.get_node_name().find("MyCustom"), std::string::npos);
}

// --- RouteLambdaTask::execute exception handling ---------------------------

TEST(RouteAdapters, RouteLambdaTaskCatchesStdExceptionAndSets500) {
    auto sess = std::make_shared<MockSession>();
    auto ctx  = make_bare_ctx(sess);
    qb::http::RouteLambdaTask<MockSession> task([](auto /*c*/) { throw std::runtime_error("boom"); }, "ThrowingLambda");
    EXPECT_EQ(task.name(), "ThrowingLambda");
    task.execute(ctx);
    EXPECT_EQ(ctx->response().status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(ctx->is_completed());
}

TEST(RouteAdapters, RouteLambdaTaskCatchesNonStdExceptionAndSets500) {
    auto sess = std::make_shared<MockSession>();
    auto ctx  = make_bare_ctx(sess);
    qb::http::RouteLambdaTask<MockSession> task([](auto /*c*/) { throw 99; }, "NonStdLambda");
    task.execute(ctx);
    EXPECT_EQ(ctx->response().status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(ctx->response().body().as<std::string>(), "Unknown internal server error in route handler.");
    EXPECT_TRUE(ctx->is_completed());
}

TEST(RouteAdapters, RouteLambdaTaskNullCtxStdExceptionDoesNotCrash) {
    // The `ctx == nullptr` logging arm: execute with a null context. The handler
    // throws, and the adapter must log-without-ctx and NOT dereference the null.
    qb::http::RouteLambdaTask<MockSession> task([](auto /*c*/) { throw std::runtime_error("no-ctx"); }, "NullCtxLambda");
    EXPECT_NO_THROW(task.execute(nullptr));
}

TEST(RouteAdapters, RouteLambdaTaskNullCtxNonStdExceptionDoesNotCrash) {
    qb::http::RouteLambdaTask<MockSession> task([](auto /*c*/) { throw 1; }, "NullCtxNonStdLambda");
    EXPECT_NO_THROW(task.execute(nullptr));
}

TEST(RouteAdapters, RouteLambdaTaskCancelIsNoop) {
    qb::http::RouteLambdaTask<MockSession> task([](auto c) { c->complete(); });
    EXPECT_NO_THROW(task.cancel());
}

// --- CustomRouteAdapterTask::execute exception handling --------------------

TEST(RouteAdapters, CustomRouteAdapterCatchesStdExceptionAndSets500) {
    auto sess   = std::make_shared<MockSession>();
    auto ctx    = make_bare_ctx(sess);
    auto custom = std::make_shared<ConfigurableCustomRoute>(ConfigurableCustomRoute::Mode::ThrowStd, "StdThrower");
    qb::http::CustomRouteAdapterTask<MockSession> task(custom);
    EXPECT_EQ(task.name(), "StdThrower");
    task.execute(ctx);
    EXPECT_EQ(ctx->response().status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(ctx->is_completed());
}

TEST(RouteAdapters, CustomRouteAdapterCatchesNonStdExceptionAndSets500) {
    auto sess   = std::make_shared<MockSession>();
    auto ctx    = make_bare_ctx(sess);
    auto custom = std::make_shared<ConfigurableCustomRoute>(ConfigurableCustomRoute::Mode::ThrowNonStd, "NonStdThrower");
    qb::http::CustomRouteAdapterTask<MockSession> task(custom);
    task.execute(ctx);
    EXPECT_EQ(ctx->response().status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(ctx->response().body().as<std::string>(), "Unknown internal server error in custom route handler.");
    EXPECT_TRUE(ctx->is_completed());
}

TEST(RouteAdapters, CustomRouteAdapterNullCtxStdExceptionDoesNotCrash) {
    auto custom = std::make_shared<ConfigurableCustomRoute>(ConfigurableCustomRoute::Mode::ThrowStd);
    qb::http::CustomRouteAdapterTask<MockSession> task(custom);
    EXPECT_NO_THROW(task.execute(nullptr));
}

TEST(RouteAdapters, CustomRouteAdapterNullCtxNonStdExceptionDoesNotCrash) {
    auto custom = std::make_shared<ConfigurableCustomRoute>(ConfigurableCustomRoute::Mode::ThrowNonStd);
    qb::http::CustomRouteAdapterTask<MockSession> task(custom);
    EXPECT_NO_THROW(task.execute(nullptr));
}

// --- CustomRouteAdapterTask::cancel delegation -----------------------------

TEST(RouteAdapters, CustomRouteAdapterCancelDelegatesToCustomRoute) {
    auto custom = std::make_shared<ConfigurableCustomRoute>(ConfigurableCustomRoute::Mode::CompleteOk);
    qb::http::CustomRouteAdapterTask<MockSession> task(custom);
    task.cancel();
    EXPECT_EQ(custom->cancel_calls, 1);
}

TEST(RouteAdapters, CustomRouteAdapterCancelSwallowsCustomRouteException) {
    auto custom = std::make_shared<ConfigurableCustomRoute>(ConfigurableCustomRoute::Mode::CompleteOk);
    custom->set_cancel_throws(true);
    qb::http::CustomRouteAdapterTask<MockSession> task(custom);
    EXPECT_NO_THROW(task.cancel());
    EXPECT_EQ(custom->cancel_calls, 1);
}

} // namespace

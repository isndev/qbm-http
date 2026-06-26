/**
 * @file qbm/http/tests/unit/middleware/middleware-transform.cpp
 * @brief Unit tests for qb::http::TransformMiddleware (request-mutation flow-control).
 *
 * TransformMiddleware runs a user RequestTransformer against ctx->request() before
 * the chain continues. These tests cover header/body/content-type/method mutation,
 * the null-transformer pass-through, the fail-closed 500 on a throwing transformer,
 * and — for the response side, which the framework expresses via PRE_RESPONSE_SEND
 * lifecycle hooks rather than a built-in response transformer — a hook that mutates
 * the outgoing response and a hook that throws (proving the router swallows it).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "../http.h"
#include "../middleware/transform.h"
#include "../routing/middleware.h"

#include "../../shared/middleware_test_fixture.h"

namespace {

/**
 * @brief Capturing session recording what the terminal handler observed about the
 *        (possibly transformed) request.
 */
struct TransformSession {
    qb::http::Response _response;
    bool               _final_handler_called = false;
    std::string        _request_body_at_handler;
    std::string        _content_type_at_handler;
    std::string        _x_transformed_value;
    bool               _x_body_cleared_present = false;
    qb::http::method   _method_at_handler      = qb::http::method::UNINITIALIZED;

    qb::http::Response &
    get_response_ref() {
        return _response;
    }

    TransformSession &
    operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    void
    reset() {
        _response = qb::http::Response();
        _final_handler_called = false;
        _request_body_at_handler.clear();
        _content_type_at_handler.clear();
        _x_transformed_value.clear();
        _x_body_cleared_present = false;
        _method_at_handler      = qb::http::method::UNINITIALIZED;
    }
};

} // namespace

/**
 * @brief Fixture providing a capturing terminal handler for request-transform tests.
 */
class TransformMiddlewareTest : public qb::http::test::MiddlewareTestFixture<TransformSession> {
protected:
    /** @brief Terminal handler that snapshots the request as seen post-transform and emits a fixed body. */
    qb::http::RouteHandlerFn<TransformSession>
    capturing_handler() {
        return [this](std::shared_ptr<qb::http::Context<TransformSession>> ctx) {
            _session->_final_handler_called    = true;
            _session->_request_body_at_handler = ctx->request().body().as<std::string>();
            _session->_method_at_handler       = ctx->request().method();
            if (ctx->request().has_header(std::string("X-Request-Transformed")))
                _session->_x_transformed_value = std::string(ctx->request().header(std::string("X-Request-Transformed")));
            _session->_x_body_cleared_present = ctx->request().has_header(std::string("X-Body-Cleared"));
            if (ctx->request().has_header(std::string("Content-Type")))
                _session->_content_type_at_handler = std::string(ctx->request().header(std::string("Content-Type")));
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Initial Handler Response Body";
            ctx->complete();
        };
    }

    /** @brief Builds a request with an optional body (Content-Type: text/plain when a body is given). */
    qb::http::Request
    body_request(const std::string &body, qb::http::method m = qb::http::method::POST, const std::string &path = "/mw_test") {
        auto req     = create_request(m, path);
        if (!body.empty()) {
            req.body() = body;
            req.set_header("Content-Type", "text/plain");
        }
        return req;
    }

    /** @brief Wires the transform middleware ahead of the capturing handler (GET+POST), compiles, routes one request. */
    void
    run_with(std::shared_ptr<qb::http::TransformMiddleware<TransformSession>> mw, qb::http::Request request) {
        _router = std::make_unique<qb::http::Router<TransformSession>>();
        _router->use(std::move(mw));
        _router->get("/mw_test", capturing_handler());
        _router->post("/mw_test", capturing_handler());
        _router->compile();
        _session->reset();
        _router->route(_session, std::move(request));
    }
};

// --- Request-side transformation --------------------------------------------

TEST_F(TransformMiddlewareTest, RequestHeaderAndBodyTransformation) {
    auto transformer = [](qb::http::Request &req) {
        req.set_header("X-Request-Transformed", "true");
        req.body() = "Transformed:" + req.body().as<std::string>();
    };
    run_with(qb::http::transform_middleware<TransformSession>(transformer, "ReqTransformer"), body_request("OriginalBody"));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_request_body_at_handler, "Transformed:OriginalBody");
    EXPECT_EQ(_session->_x_transformed_value, "true");
}

TEST_F(TransformMiddlewareTest, RequestContentTypeTransform) {
    auto transformer = [](qb::http::Request &req) {
        req.set_header("Content-Type", "application/json");
        req.body() = "JSON:" + req.body().as<std::string>();
    };
    run_with(qb::http::transform_middleware<TransformSession>(transformer), body_request("Data"));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_request_body_at_handler, "JSON:Data");
    EXPECT_EQ(_session->_content_type_at_handler, "application/json");
}

TEST_F(TransformMiddlewareTest, RequestBodyClearedByTransformer) {
    auto transformer = [](qb::http::Request &req) {
        req.body().clear();
        req.set_header("X-Body-Cleared", "true");
    };
    run_with(qb::http::transform_middleware<TransformSession>(transformer, "BodyClearer"), body_request("InitialNonEmptyBody"));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_TRUE(_session->_request_body_at_handler.empty());
    EXPECT_TRUE(_session->_x_body_cleared_present);
}

TEST_F(TransformMiddlewareTest, NullTransformerIsPassThrough) {
    run_with(qb::http::transform_middleware<TransformSession>(nullptr, "NullTransformer"),
             create_request(qb::http::method::GET, "/mw_test"));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Initial Handler Response Body");
    EXPECT_TRUE(_session->_response.header(std::string("X-Request-Transformed")).empty());
}

TEST_F(TransformMiddlewareTest, FactoryDefaultName) {
    auto mw = qb::http::transform_middleware<TransformSession>();
    ASSERT_NE(mw, nullptr);
    EXPECT_EQ(mw->name(), "TransformMiddleware");
}

// --- Method change: route already matched, so handler still runs with new method,
//     but a method with NO route genuinely misses. ----------------------------

TEST_F(TransformMiddlewareTest, RequestMethodChangedAfterMatchHandlerStillRunsWithNewMethod) {
    // Route matching happens before this middleware runs, so changing POST->PUT does not
    // re-route: the originally-matched POST handler runs, observing the mutated method.
    auto transformer = [](qb::http::Request &req) { req.method() = qb::http::method::PUT; };

    _router = std::make_unique<qb::http::Router<TransformSession>>();
    _router->use(qb::http::transform_middleware<TransformSession>(transformer, "MethodChanger"));
    _router->post("/mw_test", capturing_handler()); // only a POST route exists
    _router->compile();
    _session->reset();
    _router->route(_session, body_request("SomeBody", qb::http::method::POST));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_method_at_handler, qb::http::method::PUT);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(TransformMiddlewareTest, MethodWithNoRouteMisses) {
    // A request whose method has no matching route never reaches a handler: a real miss.
    auto noop = [](qb::http::Request &) {};
    _router   = std::make_unique<qb::http::Router<TransformSession>>();
    _router->use(qb::http::transform_middleware<TransformSession>(noop, "NoopTransformer"));
    _router->post("/mw_test", capturing_handler()); // only POST registered
    _router->compile();
    _session->reset();
    _router->route(_session, create_request(qb::http::method::GET, "/mw_test")); // GET → no route

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_NE(_session->_response.status(), qb::http::status::OK);
}

// --- Fail-closed: throwing transformer → deterministic 500 + body ------------

TEST_F(TransformMiddlewareTest, RequestTransformerThrowsReturnsInternalServerError) {
    auto throwing = [](qb::http::Request &) -> void { throw std::runtime_error("transformer boom"); };

    _router = std::make_unique<qb::http::Router<TransformSession>>();
    _router->use(qb::http::transform_middleware<TransformSession>(throwing, "ThrowingTransformer"));
    _router->post("/mw_test", capturing_handler());
    _router->compile();
    _session->reset();
    EXPECT_NO_THROW(_router->route(_session, body_request("OriginalBody")));

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->get_response_ref().status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_session->get_response_ref().body().as<std::string>(), "Error during request transformation.");
}

// --- Response-side transformation via a PRE_RESPONSE_SEND lifecycle hook ------
// The framework has no built-in ResponseTransformer; response mutation is done by
// registering a lifecycle hook. These two cases pin that contract.

TEST_F(TransformMiddlewareTest, ResponseSideTransformViaLifecycleHook) {
    // A transform middleware that registers a response-side hook mutating the outgoing body/header.
    auto request_marker = [](qb::http::Request &req) { req.set_header("X-Request-Transformed", "true"); };

    _router = std::make_unique<qb::http::Router<TransformSession>>();
    _router->use(qb::http::transform_middleware<TransformSession>(request_marker, "ReqMarker"));
    _router->get("/mw_test", [this](std::shared_ptr<qb::http::Context<TransformSession>> ctx) {
        _session->_final_handler_called = true;
        ctx->add_lifecycle_hook([](qb::http::Context<TransformSession> &c, qb::http::HookPoint point) {
            if (point == qb::http::HookPoint::PRE_RESPONSE_SEND) {
                c.response().body() = "Transformed:" + c.response().body().as<std::string>();
                c.response().set_header("X-Response-Transformed", "true");
            }
        });
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "Body";
        ctx->complete();
    });
    _router->compile();
    _session->reset();
    _router->route(_session, create_request(qb::http::method::GET, "/mw_test"));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Transformed:Body");
    EXPECT_EQ(std::string(_session->_response.header(std::string("X-Response-Transformed"))), "true");
}

TEST_F(TransformMiddlewareTest, ThrowingResponseHookIsSwallowedRequestStillCompletes) {
    // A PRE_RESPONSE_SEND hook that throws must be swallowed by the router; the
    // already-produced response is delivered and processing does not crash.
    _router = std::make_unique<qb::http::Router<TransformSession>>();
    _router->use(qb::http::transform_middleware<TransformSession>(nullptr, "NullTransformer"));
    _router->get("/mw_test", [this](std::shared_ptr<qb::http::Context<TransformSession>> ctx) {
        _session->_final_handler_called = true;
        ctx->add_lifecycle_hook([](qb::http::Context<TransformSession> &, qb::http::HookPoint point) {
            if (point == qb::http::HookPoint::PRE_RESPONSE_SEND)
                throw std::runtime_error("response hook boom");
        });
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "Body";
        ctx->complete();
    });
    _router->compile();
    _session->reset();
    EXPECT_NO_THROW(_router->route(_session, create_request(qb::http::method::GET, "/mw_test")));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Body");
}

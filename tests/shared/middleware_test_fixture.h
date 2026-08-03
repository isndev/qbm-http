/**
 * @file qbm/http/tests/shared/middleware_test_fixture.h
 * @brief Shared gtest fixture + mock session for the middleware unit test family.
 *
 * Every middleware unit test (cors, logging, auth, timing, ...) follows the same
 * shape: a capturing mock session, a freshly-built @ref qb::http::Router, a
 * request factory, a trivial success handler, and a `configure_router_and_run`
 * step that wires the middleware-under-test ahead of the handler, compiles, and
 * drives one request. This header reconciles those copies into:
 *
 *   - @ref qb::http::test::MockMiddlewareSession — minimal capturing session
 *     (operator<<, get_response_ref, reset, `_final_handler_called`).
 *   - @ref qb::http::test::MiddlewareTestFixture<SessionType> — a `::testing::Test`
 *     base that owns the session + router, rebuilds the router per test (and again
 *     per `configure_router_and_run` for a clean slate), exposes `create_request`
 *     and `basic_handler`, and runs a configured middleware chain end-to-end.
 *
 * Consuming tests typically `using MyTest = MiddlewareTestFixture<MockMiddlewareSession>;`
 * (or derive from it with a richer session type that still provides `operator<<`,
 * `get_response_ref`, `reset`, and `_final_handler_called`).
 *
 * Header-only; the fixture and session are templates / inline, so including it from
 * many gtest translation units introduces no ODR hazard.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#ifndef QB_HTTP_TESTS_SHARED_MIDDLEWARE_TEST_FIXTURE_H
#define QB_HTTP_TESTS_SHARED_MIDDLEWARE_TEST_FIXTURE_H

#include <exception>
#include <memory>
#include <string>
#include <utility>

#include <gtest/gtest.h>

#include <qbm/http/http.h> // qb::http::Router, Request, Response, Context, RouteHandlerFn, method, status

namespace qb::http::test {

/**
 * @brief Minimal capturing session for middleware unit tests.
 *
 * Implements the session-write contract used by the router (`operator<<`) and adds
 * a `_final_handler_called` flag so a test can assert whether the terminal route
 * handler ran (vs. being short-circuited by the middleware under test).
 */
struct MockMiddlewareSession {
    qb::http::Response _response;                                 ///< Last captured response.
    std::string        _session_id_str       = "mw_test_session"; ///< Human-readable id.
    bool               _final_handler_called = false;             ///< Set when the terminal handler ran.

    /** @brief Mutable access to the captured response. */
    [[nodiscard]] qb::http::Response &
    get_response_ref() {
        return _response;
    }

    /** @brief Captures the finalized response written by the router. */
    MockMiddlewareSession &
    operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    /** @brief Resets the captured response and handler flag. */
    void
    reset() {
        _response             = qb::http::Response();
        _final_handler_called = false;
    }
};

/**
 * @brief Reusable gtest fixture for exercising a single middleware in a router.
 *
 * Owns a shared @p SessionType and a `unique_ptr<Router<SessionType>>`, rebuilding
 * the router in @ref SetUp (and again in @ref configure_router_and_run) so each
 * test — and each run within a test — starts from a clean routing tree.
 *
 * @tparam SessionType A session type providing `operator<<(const Response&)`,
 *                     `get_response_ref()`, `reset()`, and a public
 *                     `_final_handler_called` member. Defaults to
 *                     @ref MockMiddlewareSession.
 */
template <typename SessionType = MockMiddlewareSession>
class MiddlewareTestFixture : public ::testing::Test {
protected:
    std::shared_ptr<SessionType>                   _session; ///< The capturing session.
    std::unique_ptr<qb::http::Router<SessionType>> _router;  ///< Router rebuilt per test / per run.

    void
    SetUp() override {
        _session = std::make_shared<SessionType>();
        _router  = std::make_unique<qb::http::Router<SessionType>>();
    }

    /**
     * @brief Builds a request from a method, path, and optional query string.
     *
     * On URI parse failure a gtest non-fatal failure is recorded and a sentinel URI
     * substituted, so a malformed test input surfaces clearly rather than crashing.
     *
     * @param method_val   HTTP method. Defaults to GET.
     * @param target_path  Request path. Defaults to "/mw_test".
     * @param query_params Optional `key=value&...` string appended after '?'.
     */
    qb::http::Request
    create_request(qb::http::method method_val = qb::http::method::GET, const std::string &target_path = "/mw_test",
                   const std::string &query_params = "") {
        qb::http::Request req;
        req.method()          = method_val;
        std::string full_path = target_path;
        if (!query_params.empty()) {
            full_path += "?" + query_params;
        }
        try {
            req.uri() = qb::io::uri(full_path);
        } catch (const std::exception &e) {
            ADD_FAILURE() << "URI parse failure: " << full_path << " (" << e.what() << ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        req.major_version = 1;
        req.minor_version = 1;
        return req;
    }

    /**
     * @brief Returns a terminal route handler that marks the session and responds.
     *
     * The handler sets `_session->_final_handler_called = true`, applies the given
     * status and a fixed body, then completes the context.
     *
     * @param status_to_return Status the handler responds with. Defaults to 200 OK.
     */
    qb::http::RouteHandlerFn<SessionType>
    basic_handler(qb::http::status status_to_return = qb::http::status::OK) {
        return [this, status_to_return](std::shared_ptr<qb::http::Context<SessionType>> ctx) {
            if (_session) {
                _session->_final_handler_called = true;
            }
            ctx->response().status() = status_to_return;
            ctx->response().body()   = "HandlerResponse";
            ctx->complete();
        };
    }

    /**
     * @brief Wires the middleware ahead of a handler, compiles, and runs one request.
     *
     * Rebuilds the router for a clean slate, registers @p middleware as global
     * middleware, mounts @ref basic_handler on @p path for both GET and POST,
     * compiles, resets the session, then routes @p request.
     *
     * @tparam MiddlewarePtr Any type accepted by `Router::use` (a shared_ptr to an
     *                       IMiddleware, a middleware factory result, etc.).
     * @param middleware     The middleware instance to place before the handler.
     * @param request        The request to drive through the chain.
     * @param handler_status Status the terminal handler returns. Defaults to 200 OK.
     * @param path           The route path to mount. Defaults to "/mw_test".
     */
    template <typename MiddlewarePtr>
    void
    configure_router_and_run(MiddlewarePtr middleware, qb::http::Request request, qb::http::status handler_status = qb::http::status::OK,
                             const std::string &path = "/mw_test") {
        _router = std::make_unique<qb::http::Router<SessionType>>();
        _router->use(std::move(middleware));
        _router->get(path, basic_handler(handler_status));
        _router->post(path, basic_handler(handler_status));
        _router->compile();

        _session->reset();
        _router->route(_session, std::move(request));
    }
};

} // namespace qb::http::test

#endif // QB_HTTP_TESTS_SHARED_MIDDLEWARE_TEST_FIXTURE_H

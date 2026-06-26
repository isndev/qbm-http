/**
 * @file qbm/http/tests/shared/mock_session.h
 * @brief Shared mock HTTP session and request/handler helpers for router tests.
 *
 * The qb-http @ref qb::http::Router writes the finalized @ref qb::http::Response of
 * each request back to its session via `session << response` (the same contract a
 * real server connection implements). For unit tests we substitute a lightweight
 * in-memory session that simply *captures* that response so assertions can inspect
 * it after `Router::route()` returns.
 *
 * This header provides the canonical implementation reconciled from the many
 * hand-rolled copies that previously lived inline in the routing test files:
 *   - @ref qb::http::test::MockSession — the capturing session (operator<<, id(),
 *     reset(), get_response_ref(), throw-on-double-write, plus the bookkeeping
 *     fields the verifying handler records into).
 *   - @ref qb::http::test::create_request — builds an HTTP/1.1 @ref qb::http::Request
 *     from a method + target path.
 *   - @ref qb::http::test::make_verifying_handler — a route handler that marks
 *     execution, records the matched handler id, and snapshots the path parameters
 *     into the session, then completes the context with 200 OK.
 *
 * Header-only; everything is `inline` / a template so the header may be included by
 * any number of gtest translation units without ODR violations.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#ifndef QB_HTTP_TESTS_SHARED_MOCK_SESSION_H
#define QB_HTTP_TESTS_SHARED_MOCK_SESSION_H

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include <qb/uuid.h> // qb::uuid, qb::generate_random_uuid

#include "../../http.h" // qb::http::Router, Request, Response, Context, PathParameters, method, status

namespace qb::http::test {

/**
 * @brief In-memory HTTP session that captures the response a Router finalizes.
 *
 * Satisfies the implicit "session" concept the router writes through: it exposes
 * `operator<<(const Response&)` (invoked exactly once per request by the router's
 * finalization callback) and an `id()`. Beyond the strict contract it carries a
 * handful of bookkeeping fields used by @ref make_verifying_handler so a test can
 * assert *which* handler ran and *what* path parameters it saw.
 *
 * The session enforces a single write between resets: a second `operator<<`
 * without an intervening @ref reset throws, surfacing accidental double-finalization
 * (a real bug class the router must never produce).
 */
struct MockSession {
    qb::http::Response       _response;                                   ///< Last captured response.
    qb::uuid                 _session_id           = qb::generate_random_uuid(); ///< Stable per-session id.
    unsigned int             _response_write_count = 0;                   ///< operator<< invocations since last reset.

    // --- Bookkeeping populated by make_verifying_handler --------------------
    bool                     _handler_executed = false; ///< Set true when a verifying handler runs.
    std::string              _handler_id;               ///< Id of the verifying handler that ran.
    qb::http::PathParameters _captured_params;          ///< Path params snapshot at handler time.

    /** @brief Mutable access to the captured response (pre-route inspection / setup). */
    [[nodiscard]] qb::http::Response &
    get_response_ref() {
        return _response;
    }

    /**
     * @brief Captures the finalized response written by the router.
     * @throws std::runtime_error if invoked more than once between resets.
     */
    MockSession &
    operator<<(const qb::http::Response &response) {
        _response = response;
        ++_response_write_count;
        if (_response_write_count > 1) {
            throw std::runtime_error("MockSession::operator<< called " + std::to_string(_response_write_count)
                                     + " times. Expected no more than 1 call between resets.");
        }
        return *this;
    }

    /** @brief Stable session identifier. */
    [[nodiscard]] const qb::uuid &
    id() const noexcept {
        return _session_id;
    }

    /** @brief Resets captured response, write counter, and verifying-handler bookkeeping. */
    void
    reset() {
        _response             = qb::http::Response();
        _response_write_count = 0;
        _handler_executed     = false;
        _handler_id.clear();
        _captured_params.clear();
    }

    /**
     * @brief How many times the router finalized (wrote) a response since the last reset.
     * @return Expected 1 after a single successful route() call, 0 if nothing was written.
     */
    [[nodiscard]] unsigned int
    response_write_count() const noexcept {
        return _response_write_count;
    }
};

/**
 * @brief Builds an HTTP/1.1 request from a method and target path.
 *
 * The path may include a query string (e.g. "/items?id=3"); it is parsed into the
 * request URI. The protocol version is fixed to 1.1.
 *
 * @tparam SessionType Unused; templated only so the helper can live beside the
 *                     session-templated helpers without forcing an explicit arg.
 *                     Prefer the non-template overload below for the common case.
 * @param method_val  The HTTP method (e.g. `qb::http::method::GET`).
 * @param target_path The request target / path (optionally with a query string).
 * @return A populated @ref qb::http::Request.
 */
inline qb::http::Request
create_request(qb::http::method method_val, const std::string &target_path) {
    qb::http::Request req;
    req.method()      = method_val;
    req.uri()         = qb::io::uri(target_path);
    req.major_version = 1;
    req.minor_version = 1;
    return req;
}

/**
 * @brief Creates a route handler that records execution into its session and returns 200 OK.
 *
 * The produced handler, when invoked by the router, marks `_handler_executed`,
 * stores `handler_id` in `_handler_id`, snapshots the matched path parameters into
 * `_captured_params`, sets the response status to 200 OK, and completes the context.
 * This lets routing-match tests assert *which* route won and *what* it captured.
 *
 * @tparam SessionType A session type exposing `_handler_executed`, `_handler_id`,
 *                     and `_captured_params` (e.g. @ref MockSession).
 * @param handler_id  Identifier recorded when this handler runs.
 * @return A `qb::http::RouteHandlerFn<SessionType>`-compatible lambda.
 */
template <typename SessionType>
[[nodiscard]] inline auto
make_verifying_handler(const std::string &handler_id) {
    return [handler_id](std::shared_ptr<qb::http::Context<SessionType>> ctx) {
        if (auto session = ctx->session()) {
            session->_handler_executed = true;
            session->_handler_id       = handler_id;
            session->_captured_params  = ctx->path_parameters();
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    };
}

} // namespace qb::http::test

#endif // QB_HTTP_TESTS_SHARED_MOCK_SESSION_H

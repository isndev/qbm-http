/**
 * @file qbm/http/tests/unit/middleware/middleware-logging.cpp
 * @brief Unit tests for qb::http::LoggingMiddleware (request/response log emission).
 *
 * LoggingMiddleware logs one Info "Request: <METHOD> <path>" line on process() and one
 * "Response: <status>" line from a PRE_RESPONSE_SEND hook. These tests pin the exact
 * entry count, levels, path formatting (query deliberately excluded; trailing slash
 * preserved verbatim by qb::io::uri::path()), the lifecycle-hook survival across
 * middleware destruction, the null-logger guard, naming, and relative ordering when
 * the logging middleware sits ahead of another middleware in the chain.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "../http.h"
#include "../middleware/logging.h"
#include "../routing/middleware.h"

#include "../../shared/middleware_test_fixture.h"

namespace {

/**
 * @brief Capturing session for logging tests: records (level, message) pairs plus an
 *        ordered event trace for multi-middleware ordering assertions.
 */
struct LoggingSession {
    qb::http::Response                                      _response;
    std::vector<std::pair<qb::http::LogLevel, std::string>> _log_entries;
    std::vector<std::string>                                _order_trace;
    bool                                                    _final_handler_called = false;

    qb::http::Response &
    get_response_ref() {
        return _response;
    }

    LoggingSession &
    operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    void
    reset() {
        _response = qb::http::Response();
        _log_entries.clear();
        _order_trace.clear();
        _final_handler_called = false;
    }
};

using LoggingMW = qb::http::LoggingMiddleware<LoggingSession>;

/** @brief Trivial middleware recording a marker into the session order trace, then CONTINUEs. */
class OrderTracerMiddleware : public qb::http::IMiddleware<LoggingSession> {
public:
    explicit OrderTracerMiddleware(std::string marker)
        : _marker(std::move(marker)) {}

    void
    process(std::shared_ptr<qb::http::Context<LoggingSession>> ctx) override {
        if (ctx->session())
            ctx->session()->_order_trace.push_back(_marker);
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }

    [[nodiscard]] std::string
    name() const override {
        return _marker;
    }

    void
    cancel() override {}

private:
    std::string _marker;
};

} // namespace

/**
 * @brief Fixture for LoggingMiddleware: provides a logger capturing into the session.
 */
class LoggingMiddlewareTest : public qb::http::test::MiddlewareTestFixture<LoggingSession> {
protected:
    LoggingMW::LogFunction _logger;

    void
    SetUp() override {
        MiddlewareTestFixture<LoggingSession>::SetUp();
        _logger = [this](qb::http::LogLevel level, const std::string &message) {
            if (_session)
                _session->_log_entries.push_back({level, message});
        };
    }

    /** @brief Mounts the logging middleware ahead of a basic handler on @p path, compiles, routes one request. */
    void
    run_single_route(std::shared_ptr<LoggingMW> mw, qb::http::Request request, const std::string &path,
                     qb::http::status handler_status = qb::http::status::OK) {
        _router = std::make_unique<qb::http::Router<LoggingSession>>();
        _router->use(std::move(mw));
        _router->get(path, basic_handler(handler_status));
        _router->post(path, basic_handler(handler_status));
        _router->del(path, basic_handler(handler_status));
        _router->compile();
        _session->reset();
        _router->route(_session, std::move(request));
    }
};

// --- Basic emission ----------------------------------------------------------

TEST_F(LoggingMiddlewareTest, BasicRequestAndResponseLogging) {
    run_single_route(qb::http::logging_middleware<LoggingSession>(_logger), create_request(qb::http::method::GET, "/log_test"),
                     "/log_test");

    ASSERT_EQ(_session->_log_entries.size(), 2u);
    EXPECT_EQ(_session->_log_entries[0].first, qb::http::LogLevel::Info);
    EXPECT_NE(_session->_log_entries[0].second.find("Request: GET /log_test"), std::string::npos);
    EXPECT_EQ(_session->_log_entries[1].first, qb::http::LogLevel::Debug);
    EXPECT_NE(_session->_log_entries[1].second.find("Response: 200"), std::string::npos);
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(LoggingMiddlewareTest, CustomLogLevels) {
    run_single_route(
        qb::http::logging_middleware<LoggingSession>(_logger, qb::http::LogLevel::Debug, qb::http::LogLevel::Warning),
        create_request(qb::http::method::GET, "/log_test"), "/log_test", qb::http::status::NOT_FOUND);

    ASSERT_EQ(_session->_log_entries.size(), 2u);
    EXPECT_EQ(_session->_log_entries[0].first, qb::http::LogLevel::Debug);
    EXPECT_EQ(_session->_log_entries[1].first, qb::http::LogLevel::Warning);
    EXPECT_NE(_session->_log_entries[1].second.find("Response: 404"), std::string::npos);
}

TEST_F(LoggingMiddlewareTest, DifferentHttpMethodsLogged) {
    run_single_route(qb::http::logging_middleware<LoggingSession>(_logger), create_request(qb::http::method::POST, "/log_test"),
                     "/log_test");
    ASSERT_EQ(_session->_log_entries.size(), 2u);
    EXPECT_NE(_session->_log_entries[0].second.find("Request: POST /log_test"), std::string::npos);
}

TEST_F(LoggingMiddlewareTest, ErrorResponseLogged) {
    run_single_route(qb::http::logging_middleware<LoggingSession>(_logger), create_request(qb::http::method::GET, "/log_test"),
                     "/log_test", qb::http::status::INTERNAL_SERVER_ERROR);
    ASSERT_EQ(_session->_log_entries.size(), 2u);
    EXPECT_NE(_session->_log_entries[1].second.find("Response: 500"), std::string::npos);
}

TEST_F(LoggingMiddlewareTest, VariousStatusCodesRendered) {
    struct Case {
        qb::http::method method;
        std::string      path;
        qb::http::status status;
        std::string      expect;
    };
    const Case cases[] = {
        {qb::http::method::GET, "/path101", qb::http::status::SWITCHING_PROTOCOLS, "Response: 101"},
        {qb::http::method::POST, "/path201", qb::http::status::CREATED, "Response: 201"},
        {qb::http::method::DEL, "/path204", qb::http::status::NO_CONTENT, "Response: 204"},
        {qb::http::method::GET, "/path302", qb::http::status::FOUND, "Response: 302"},
    };
    for (const auto &c : cases) {
        run_single_route(qb::http::logging_middleware<LoggingSession>(_logger), create_request(c.method, c.path), c.path, c.status);
        ASSERT_EQ(_session->_log_entries.size(), 2u) << c.path;
        EXPECT_NE(_session->_log_entries[1].second.find(c.expect), std::string::npos) << c.path;
    }
}

// --- Path formatting contract ------------------------------------------------

TEST_F(LoggingMiddlewareTest, QueryParametersExcludedFromRequestLog) {
    auto mw = qb::http::logging_middleware<LoggingSession>(_logger);
    _router = std::make_unique<qb::http::Router<LoggingSession>>();
    _router->use(mw);
    _router->get("/log_test_query", basic_handler());
    _router->compile();
    _session->reset();
    _router->route(_session, create_request(qb::http::method::GET, "/log_test_query", "param1=value1&param2=value2"));

    ASSERT_EQ(_session->_log_entries.size(), 2u);
    const std::string &msg = _session->_log_entries[0].second;
    EXPECT_NE(msg.find("Request: GET /log_test_query"), std::string::npos);
    EXPECT_EQ(msg.find("param1=value1"), std::string::npos);
    EXPECT_EQ(msg.find("param2=value2"), std::string::npos);
    EXPECT_EQ(msg.find('?'), std::string::npos);
}

TEST_F(LoggingMiddlewareTest, RootPathLogged) {
    run_single_route(qb::http::logging_middleware<LoggingSession>(_logger), create_request(qb::http::method::GET, "/"), "/");
    ASSERT_EQ(_session->_log_entries.size(), 2u);
    EXPECT_NE(_session->_log_entries[0].second.find("Request: GET /"), std::string::npos);
}

TEST_F(LoggingMiddlewareTest, TrailingSlashPreservedVerbatim) {
    // qb::io::uri::path() returns the path component unmodified, so format_request_info()
    // logs the trailing slash exactly as supplied — deterministic, not normalization-dependent.
    run_single_route(qb::http::logging_middleware<LoggingSession>(_logger),
                     create_request(qb::http::method::GET, "/trailing/"), "/trailing/");
    ASSERT_EQ(_session->_log_entries.size(), 2u);
    const std::string &with_slash = _session->_log_entries[0].second;
    EXPECT_NE(with_slash.find("Request: GET /trailing/"), std::string::npos);
    // Contrast: the non-trailing form logs WITHOUT the slash — proving verbatim, not collapsed.
    EXPECT_EQ(with_slash.find("Request: GET /trailing "), std::string::npos);
    EXPECT_EQ(with_slash.find("Request: GET /trailing\n"), std::string::npos);

    run_single_route(qb::http::logging_middleware<LoggingSession>(_logger),
                     create_request(qb::http::method::GET, "/trailing"), "/trailing");
    ASSERT_EQ(_session->_log_entries.size(), 2u);
    const std::string &no_slash = _session->_log_entries[0].second;
    EXPECT_NE(no_slash.find("Request: GET /trailing"), std::string::npos);
    EXPECT_EQ(no_slash.find("Request: GET /trailing/"), std::string::npos);
}

// --- Lifecycle-hook survival -------------------------------------------------

TEST_F(LoggingMiddlewareTest, ResponseHookSurvivesMiddlewareDestruction) {
    auto mw  = qb::http::logging_middleware<LoggingSession>(_logger);
    auto ctx = std::make_shared<qb::http::Context<LoggingSession>>(
        create_request(qb::http::method::GET, "/log_test"), qb::http::Response{}, _session,
        [](qb::http::Context<LoggingSession> &) {}, std::weak_ptr<qb::http::RouterCore<LoggingSession>>{});

    mw->process(ctx);
    mw.reset(); // destroy middleware; the response-log hook closure must survive

    ctx->response().status() = qb::http::status::CREATED;
    ctx->execute_hook(qb::http::HookPoint::PRE_RESPONSE_SEND);

    ASSERT_EQ(_session->_log_entries.size(), 2u);
    EXPECT_NE(_session->_log_entries[1].second.find("Response: 201"), std::string::npos);
}

// --- Guards & naming ---------------------------------------------------------

TEST_F(LoggingMiddlewareTest, ConstructorAndFactoryThrowOnNullLogFunction) {
    LoggingMW::LogFunction null_logger = nullptr;
    EXPECT_THROW(LoggingMW logging_mw(null_logger), std::invalid_argument);
    EXPECT_THROW((void) qb::http::logging_middleware<LoggingSession>(null_logger), std::invalid_argument);
}

TEST_F(LoggingMiddlewareTest, MiddlewareNameIsCorrect) {
    LoggingMW default_ctor(_logger);
    EXPECT_EQ(default_ctor.name(), "LoggingMiddleware");

    LoggingMW custom_ctor(_logger, qb::http::LogLevel::Info, qb::http::LogLevel::Info, "MyCustomLogger");
    EXPECT_EQ(custom_ctor.name(), "MyCustomLogger");

    EXPECT_EQ(qb::http::logging_middleware<LoggingSession>(_logger)->name(), "LoggingMiddleware");
    EXPECT_EQ(qb::http::logging_middleware<LoggingSession>(_logger, qb::http::LogLevel::Info, qb::http::LogLevel::Info, "MyFactoryLogger")
                  ->name(),
              "MyFactoryLogger");
}

// --- Multi-middleware ordering ----------------------------------------------

TEST_F(LoggingMiddlewareTest, RequestLoggedOnceBeforeDownstreamMiddleware) {
    // Logging middleware first, then a tracer: the request line is emitted exactly once,
    // BEFORE the downstream middleware runs; the response line is emitted once after.
    auto logging_mw = qb::http::logging_middleware<LoggingSession>(_logger);
    auto tracer     = std::make_shared<OrderTracerMiddleware>("downstream");

    _router = std::make_unique<qb::http::Router<LoggingSession>>();
    _router->use(logging_mw);
    _router->use(tracer);
    _router->get("/ordered", [this](std::shared_ptr<qb::http::Context<LoggingSession>> ctx) {
        _session->_final_handler_called = true;
        _session->_order_trace.push_back("handler");
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "ok";
        ctx->complete();
    });
    _router->compile();
    _session->reset();
    _router->route(_session, create_request(qb::http::method::GET, "/ordered"));

    // Exactly two log entries (one request, one response): no double-emission.
    ASSERT_EQ(_session->_log_entries.size(), 2u);
    EXPECT_NE(_session->_log_entries[0].second.find("Request: GET /ordered"), std::string::npos);
    EXPECT_NE(_session->_log_entries[1].second.find("Response: 200"), std::string::npos);

    // The downstream tracer and handler ran in order after the logging middleware.
    ASSERT_EQ(_session->_order_trace.size(), 2u);
    EXPECT_EQ(_session->_order_trace[0], "downstream");
    EXPECT_EQ(_session->_order_trace[1], "handler");
    EXPECT_TRUE(_session->_final_handler_called);
}

/**
 * @file qbm/http/tests/unit/middleware/middleware-conditional.cpp
 * @brief Unit tests for qb::http::ConditionalMiddleware (flow-control middleware).
 *
 * Exercises the predicate-driven branch selection of ConditionalMiddleware: the
 * if-branch (predicate true), the else-branch (predicate false + else provided),
 * the pass-through (predicate false + no else), nesting/chaining, child branches
 * that COMPLETE the chain, and the fail-closed behaviour when the predicate or a
 * child middleware throws (the framework catches and emits a deterministic 500).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <memory>
#include <sstream>
#include <string>

#include <qbm/http/http.h>
#include <qbm/http/middleware/conditional.h>
#include <qbm/http/routing/middleware.h>

#include "../../shared/middleware_test_fixture.h"

using qb::http::test::MiddlewareTestFixture;

namespace {

/**
 * @brief Capturing session for conditional tests: records a branch trace and the
 *        request headers visible to the terminal handler.
 *
 * Satisfies the MiddlewareTestFixture session contract (operator<<, get_response_ref,
 * reset, _final_handler_called) while adding an ordered trace string.
 */
struct ConditionalSession {
    qb::http::Response _response;
    std::ostringstream _trace;
    bool               _final_handler_called = false;
    std::string        _captured_chain_header; ///< Value of X-Chain1-Passed seen by handler.

    qb::http::Response &
    get_response_ref() {
        return _response;
    }

    ConditionalSession &
    operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    void
    reset() {
        _response = qb::http::Response();
        _trace.str("");
        _trace.clear();
        _final_handler_called = false;
        _captured_chain_header.clear();
    }

    void
    trace(const std::string &point) {
        if (!_trace.str().empty())
            _trace << ";";
        _trace << point;
    }

    [[nodiscard]] std::string
    get_trace() const {
        return _trace.str();
    }
};

/** @brief Child middleware that records its id in the trace and optionally sets a request header, then CONTINUEs. */
class TracerMiddleware : public qb::http::IMiddleware<ConditionalSession> {
public:
    TracerMiddleware(std::string id, std::string header_key = "", std::string header_value = "")
        : _id(std::move(id))
        , _header_key(std::move(header_key))
        , _header_value(std::move(header_value)) {}

    void
    process(std::shared_ptr<qb::http::Context<ConditionalSession>> ctx) override {
        if (ctx->session())
            ctx->session()->trace(_id);
        if (!_header_key.empty())
            ctx->request().set_header(_header_key, _header_value);
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }

    [[nodiscard]] std::string
    name() const override {
        return _id;
    }

    void
    cancel() override {}

private:
    std::string _id, _header_key, _header_value;
};

/** @brief Child middleware that traces and COMPLETEs the chain with 204 (short-circuits the terminal handler). */
class CompletingTracerMiddleware : public qb::http::IMiddleware<ConditionalSession> {
public:
    explicit CompletingTracerMiddleware(std::string id)
        : _id(std::move(id)) {}

    void
    process(std::shared_ptr<qb::http::Context<ConditionalSession>> ctx) override {
        if (ctx->session())
            ctx->session()->trace(_id);
        ctx->response().status() = qb::http::status::NO_CONTENT;
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    }

    [[nodiscard]] std::string
    name() const override {
        return _id;
    }

    void
    cancel() override {}

private:
    std::string _id;
};

/** @brief Child middleware that traces, then throws — exercises the fail-closed catch in ConditionalMiddleware. */
class ThrowingTracerMiddleware : public qb::http::IMiddleware<ConditionalSession> {
public:
    explicit ThrowingTracerMiddleware(std::string id)
        : _id(std::move(id)) {}

    void
    process(std::shared_ptr<qb::http::Context<ConditionalSession>> ctx) override {
        if (ctx->session())
            ctx->session()->trace(_id);
        throw std::runtime_error("child middleware failure");
    }

    [[nodiscard]] std::string
    name() const override {
        return _id;
    }

    void
    cancel() override {}

private:
    std::string _id;
};

} // namespace

/**
 * @brief Fixture adding a tracing terminal handler on top of MiddlewareTestFixture.
 */
class ConditionalMiddlewareTest : public MiddlewareTestFixture<ConditionalSession> {
protected:
    /** @brief Terminal handler that traces and captures the X-Chain1-Passed header the handler sees. */
    qb::http::RouteHandlerFn<ConditionalSession>
    tracing_handler(const std::string &id = "FinalHandler") {
        return [this, id](std::shared_ptr<qb::http::Context<ConditionalSession>> ctx) {
            if (_session) {
                _session->trace(id);
                _session->_final_handler_called  = true;
                _session->_captured_chain_header = std::string(ctx->request().header(std::string("X-Chain1-Passed")));
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        };
    }

    /** @brief Wires the conditional middleware ahead of the tracing handler, compiles, and routes one request. */
    void
    run_with(std::shared_ptr<qb::http::ConditionalMiddleware<ConditionalSession>> cond_mw, qb::http::Request request) {
        _router = std::make_unique<qb::http::Router<ConditionalSession>>();
        _router->use(std::move(cond_mw));
        _router->get("/mw_test", tracing_handler());
        _router->compile();
        _session->reset();
        _router->route(_session, std::move(request));
    }
};

// --- Branch selection -------------------------------------------------------

TEST_F(ConditionalMiddlewareTest, ConditionTrueExecutesIfMiddleware) {
    auto predicate = [](const std::shared_ptr<qb::http::Context<ConditionalSession>> &ctx) {
        return ctx->request().uri().path() == "/mw_test";
    };
    auto cond_mw = qb::http::conditional_middleware<ConditionalSession>(predicate, std::make_shared<TracerMiddleware>("IfMiddleware"));

    run_with(cond_mw, create_request());

    EXPECT_EQ(_session->get_trace(), "IfMiddleware;FinalHandler");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(ConditionalMiddlewareTest, ConditionFalseWithElseExecutesElseMiddleware) {
    auto predicate = [](const std::shared_ptr<qb::http::Context<ConditionalSession>> &ctx) {
        return ctx->request().has_header(std::string("X-Execute-If"));
    };
    auto cond_mw = qb::http::conditional_middleware<ConditionalSession>(predicate, std::make_shared<TracerMiddleware>("IfMiddleware_NeverRuns"),
                                                                        std::make_shared<TracerMiddleware>("ElseMiddleware"));

    run_with(cond_mw, create_request()); // no X-Execute-If header

    EXPECT_EQ(_session->get_trace(), "ElseMiddleware;FinalHandler");
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(ConditionalMiddlewareTest, ConditionFalseWithoutElseContinues) {
    bool predicate_called = false;
    auto predicate        = [&predicate_called](const auto        &/*ctx*/) {
        predicate_called = true;
        return false;
    };
    auto cond_mw =
        qb::http::conditional_middleware<ConditionalSession>(predicate, std::make_shared<TracerMiddleware>("IfMiddleware_NeverRuns"));

    run_with(cond_mw, create_request());

    EXPECT_EQ(_session->get_trace(), "FinalHandler");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_TRUE(predicate_called);
}

// --- Context propagation / child COMPLETE -----------------------------------

TEST_F(ConditionalMiddlewareTest, ContextManipulationInPredicateAndChild) {
    auto predicate = [](const std::shared_ptr<qb::http::Context<ConditionalSession>> &ctx) {
        ctx->set("predicate_decision", std::string("took_if_branch"));
        return true;
    };
    auto if_mw   = std::make_shared<TracerMiddleware>("IfMiddlewareSetsHeader", "X-If-Action", "Performed");
    auto cond_mw = qb::http::conditional_middleware<ConditionalSession>(predicate, if_mw);

    _router = std::make_unique<qb::http::Router<ConditionalSession>>();
    _router->use(cond_mw);
    _router->get("/mw_test", [this](std::shared_ptr<qb::http::Context<ConditionalSession>> ctx) {
        _session->trace("FinalHandlerChecksContext");
        _session->_final_handler_called = true;
        auto decision_opt               = ctx->template get<std::string>("predicate_decision");
        ASSERT_TRUE(decision_opt.has_value());
        EXPECT_EQ(*decision_opt, "took_if_branch");
        EXPECT_EQ(std::string(ctx->request().header(std::string("X-If-Action"))), "Performed");
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();
    _session->reset();
    _router->route(_session, create_request());

    EXPECT_EQ(_session->get_trace(), "IfMiddlewareSetsHeader;FinalHandlerChecksContext");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(ConditionalMiddlewareTest, ConditionTrueIfCompletesShortCircuitsHandler) {
    auto predicate = [](const auto & /*ctx*/) {
        return true;
    };
    auto cond_mw =
        qb::http::conditional_middleware<ConditionalSession>(predicate, std::make_shared<CompletingTracerMiddleware>("IfMiddlewareCompletes"));

    run_with(cond_mw, create_request());

    EXPECT_EQ(_session->get_trace(), "IfMiddlewareCompletes");
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::NO_CONTENT);
}

TEST_F(ConditionalMiddlewareTest, ConditionFalseElseCompletesShortCircuitsHandler) {
    auto predicate = [](const auto & /*ctx*/) {
        return false;
    };
    auto cond_mw =
        qb::http::conditional_middleware<ConditionalSession>(predicate, std::make_shared<TracerMiddleware>("IfMiddleware_NeverRuns"),
                                                             std::make_shared<CompletingTracerMiddleware>("ElseMiddlewareCompletes"));

    run_with(cond_mw, create_request());

    EXPECT_EQ(_session->get_trace(), "ElseMiddlewareCompletes");
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::NO_CONTENT);
}

// --- Nesting & chaining ------------------------------------------------------

TEST_F(ConditionalMiddlewareTest, NestedConditionalMiddleware) {
    auto outer_predicate = [](const auto &ctx) {
        return ctx->request().has_header(std::string("X-Outer"));
    };
    auto inner_predicate = [](const auto &ctx) {
        return ctx->request().has_header(std::string("X-Inner"));
    };

    auto make_outer = [&]() {
        auto inner_cond =
            qb::http::conditional_middleware<ConditionalSession>(inner_predicate, std::make_shared<TracerMiddleware>("InnerIf"),
                                                                 std::make_shared<TracerMiddleware>("InnerElse"), "InnerConditional");
        return qb::http::conditional_middleware<ConditionalSession>(outer_predicate, inner_cond,
                                                                    std::make_shared<TracerMiddleware>("OuterElse"), "OuterConditional");
    };

    { // Outer=true, Inner=true => InnerIf
        auto req = create_request();
        req.set_header("X-Outer", "true");
        req.set_header("X-Inner", "true");
        run_with(make_outer(), std::move(req));
        EXPECT_EQ(_session->get_trace(), "InnerIf;FinalHandler");
    }
    { // Outer=true, Inner=false => InnerElse
        auto req = create_request();
        req.set_header("X-Outer", "true");
        run_with(make_outer(), std::move(req));
        EXPECT_EQ(_session->get_trace(), "InnerElse;FinalHandler");
    }
    { // Outer=false => OuterElse
        run_with(make_outer(), create_request());
        EXPECT_EQ(_session->get_trace(), "OuterElse;FinalHandler");
    }
}

TEST_F(ConditionalMiddlewareTest, ChainedConditionalsExecuteSequentially) {
    auto pred1 = [](const auto &ctx) {
        return ctx->request().uri().path() == "/mw_test";
    };
    auto if_mw1   = std::make_shared<TracerMiddleware>("Chain1If", "X-Chain1-Passed", "yes");
    auto cond_mw1 = qb::http::conditional_middleware<ConditionalSession>(pred1, if_mw1, nullptr, "CondChain1");

    auto pred2 = [](const auto &ctx) {
        return std::string(ctx->request().header(std::string("X-Chain1-Passed"))) == "yes";
    };
    auto cond_mw2 =
        qb::http::conditional_middleware<ConditionalSession>(pred2, std::make_shared<TracerMiddleware>("Chain2If"), nullptr, "CondChain2");

    _router = std::make_unique<qb::http::Router<ConditionalSession>>();
    _router->use(cond_mw1);
    _router->use(cond_mw2);
    _router->get("/mw_test", tracing_handler());
    _router->compile();
    _session->reset();
    _router->route(_session, create_request());

    EXPECT_EQ(_session->get_trace(), "Chain1If;Chain2If;FinalHandler");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_captured_chain_header, "yes");
}

// --- Predicate single-evaluation (real reuse of one middleware instance) -----

TEST_F(ConditionalMiddlewareTest, PredicateCalledOncePerRequestOnReusedInstance) {
    int  predicate_call_count = 0;
    auto predicate            = [&](const auto            &/*ctx*/) {
        ++predicate_call_count;
        return true;
    };
    // Single shared instance reused across two consecutive requests on freshly compiled routers.
    auto cond_mw = qb::http::conditional_middleware<ConditionalSession>(predicate, std::make_shared<TracerMiddleware>("IfReused"));

    run_with(cond_mw, create_request());
    EXPECT_EQ(predicate_call_count, 1);
    EXPECT_EQ(_session->get_trace(), "IfReused;FinalHandler");

    // Second request through the SAME middleware instance: predicate runs exactly once more (state is external).
    run_with(cond_mw, create_request());
    EXPECT_EQ(predicate_call_count, 2) << "Predicate must be evaluated exactly once per request, even when reused.";
    EXPECT_EQ(_session->get_trace(), "IfReused;FinalHandler");
}

// --- Fail-closed behaviour (deterministic 500 + body) ------------------------

TEST_F(ConditionalMiddlewareTest, PredicateThrowsReturnsInternalServerError) {
    auto throwing_predicate = [](const auto & /*ctx*/) -> bool {
        throw std::runtime_error("Predicate failed!");
    };
    auto cond_mw = qb::http::conditional_middleware<ConditionalSession>(throwing_predicate, std::make_shared<TracerMiddleware>("IfMiddleware"));

    run_with(cond_mw, create_request());

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Error during conditional middleware evaluation.");
}

TEST_F(ConditionalMiddlewareTest, IfMiddlewareThrowsReturnsInternalServerError) {
    auto predicate = [](const auto & /*ctx*/) {
        return true;
    };
    auto cond_mw = qb::http::conditional_middleware<ConditionalSession>(predicate, std::make_shared<ThrowingTracerMiddleware>("IfThrows"));

    run_with(cond_mw, create_request());

    EXPECT_EQ(_session->get_trace(), "IfThrows"); // traced before throwing
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Error during conditional middleware evaluation.");
}

TEST_F(ConditionalMiddlewareTest, ElseMiddlewareThrowsReturnsInternalServerError) {
    auto predicate = [](const auto & /*ctx*/) {
        return false;
    };
    auto cond_mw = qb::http::conditional_middleware<ConditionalSession>(predicate, std::make_shared<TracerMiddleware>("IfMiddleware_NeverRuns"),
                                                                        std::make_shared<ThrowingTracerMiddleware>("ElseThrows"));

    run_with(cond_mw, create_request());

    EXPECT_EQ(_session->get_trace(), "ElseThrows");
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Error during conditional middleware evaluation.");
}

// --- Constructor / factory guards -------------------------------------------

TEST_F(ConditionalMiddlewareTest, FactoryThrowsOnNullIfMiddlewareOrNullPredicate) {
    auto predicate = [](const auto & /*ctx*/) {
        return true;
    };
    std::shared_ptr<qb::http::IMiddleware<ConditionalSession>> null_if_mw    = nullptr;
    std::shared_ptr<qb::http::IMiddleware<ConditionalSession>> dummy_else_mw = std::make_shared<TracerMiddleware>("DummyElse");

    EXPECT_THROW((void) qb::http::conditional_middleware<ConditionalSession>(predicate, null_if_mw, dummy_else_mw), std::invalid_argument);

    std::shared_ptr<qb::http::IMiddleware<ConditionalSession>>     valid_if_mw    = std::make_shared<TracerMiddleware>("ValidIf");
    qb::http::ConditionalMiddleware<ConditionalSession>::Predicate null_predicate = nullptr;
    EXPECT_THROW((void) qb::http::conditional_middleware<ConditionalSession>(null_predicate, valid_if_mw, dummy_else_mw),
                 std::invalid_argument);
}

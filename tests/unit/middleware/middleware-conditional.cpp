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

#include <initializer_list>
#include <memory>
#include <optional>
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

namespace conditional_cancellation_test {
// The fields are test observations, not request dispatch state. No timer or
// scheduler is needed: returning without complete keeps this task in flight.
class PendingChild : public qb::http::IMiddleware<ConditionalSession> {
public:
    int starts        = 0;
    int cancellations = 0;

    PendingChild() = default;

    explicit PendingChild(qb::http::AsyncTaskResult result, bool throw_after_completion = false)
        : _result(result)
        , _throw_after_completion(throw_after_completion) {}

    void
    process(std::shared_ptr<qb::http::Context<ConditionalSession>> context) override {
        ++starts;
        if (_result) {
            context->complete(*_result);
            if (_throw_after_completion)
                throw std::runtime_error("child threw after completing");
        }
    }
    std::string
    name() const override {
        return "PendingChild";
    }
    void
    cancel() noexcept override {
        ++cancellations;
    }

private:
    std::optional<qb::http::AsyncTaskResult> _result;
    bool                                     _throw_after_completion = false;
};
} // namespace conditional_cancellation_test

TEST_F(ConditionalMiddlewareTest, CancellationReachesOnlyTheChildSelectedByThatContext) {
    using Context    = qb::http::Context<ConditionalSession>;
    auto if_child    = std::make_shared<conditional_cancellation_test::PendingChild>();
    auto else_child  = std::make_shared<conditional_cancellation_test::PendingChild>();
    auto conditional = qb::http::conditional_middleware<ConditionalSession>(
        [](const auto &ctx) { return ctx->request().header("X-Branch") == "if"; }, if_child, else_child);
    _router = std::make_unique<qb::http::Router<ConditionalSession>>();
    _router->use(conditional);
    _router->get("/mw_test", [](std::shared_ptr<Context> ctx) { ctx->text("finished"); });
    _router->compile();
    auto first_session  = std::make_shared<ConditionalSession>();
    auto second_session = std::make_shared<ConditionalSession>();
    auto first_request  = create_request();
    first_request.set_header("X-Branch", "if");
    auto second_request = create_request();
    second_request.set_header("X-Branch", "else");
    auto first  = _router->route(first_session, std::move(first_request));
    auto second = _router->route(second_session, std::move(second_request));
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    ASSERT_FALSE(first->is_completed());
    ASSERT_FALSE(second->is_completed());
    ASSERT_EQ(if_child->starts, 1);
    ASSERT_EQ(else_child->starts, 1);
    first->cancel("first only");
    first->cancel("duplicate cancel");
    EXPECT_EQ(if_child->cancellations, 1);
    EXPECT_EQ(else_child->cancellations, 0);
    EXPECT_TRUE(first->is_cancelled());
    EXPECT_FALSE(second->is_cancelled());
    second->complete(qb::http::AsyncTaskResult::CONTINUE);
    EXPECT_TRUE(second->is_completed());
    EXPECT_EQ(second_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(second_session->_response.body().as<std::string>(), "finished");
    first->complete(qb::http::AsyncTaskResult::CONTINUE);
    EXPECT_EQ(first_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(if_child->cancellations, 1);
    EXPECT_EQ(else_child->cancellations, 0);
}

TEST_F(ConditionalMiddlewareTest, CancellationOfTwoContextsSelectingTheSameChildIsIndependent) {
    using PendingChild = conditional_cancellation_test::PendingChild;
    auto child         = std::make_shared<PendingChild>();
    _router->use(qb::http::conditional_middleware<ConditionalSession>([](const auto &) { return true; }, child));
    _router->get("/mw_test", tracing_handler());
    _router->compile();
    auto second_session = std::make_shared<ConditionalSession>();
    auto first          = _router->route(_session, create_request());
    auto second         = _router->route(second_session, create_request());
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    ASSERT_FALSE(first->is_completed());
    ASSERT_FALSE(second->is_completed());
    ASSERT_EQ(child->starts, 2);

    first->cancel("first");
    first->cancel("first again");
    EXPECT_EQ(child->cancellations, 1);
    EXPECT_TRUE(first->is_cancelled());
    EXPECT_FALSE(second->is_cancelled());
    EXPECT_FALSE(second->is_completed());

    second->cancel("second");
    second->cancel("second again");
    EXPECT_EQ(child->cancellations, 2);
    EXPECT_TRUE(second->is_cancelled());
    EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(second_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
}

TEST_F(ConditionalMiddlewareTest, NestedCancellationReachesThePendingLeaf) {
    using PendingChild = conditional_cancellation_test::PendingChild;
    auto leaf          = std::make_shared<PendingChild>();
    auto unused        = std::make_shared<PendingChild>();
    auto inner         = qb::http::conditional_middleware<ConditionalSession>([](const auto &) { return false; }, unused, leaf);
    _router->use(qb::http::conditional_middleware<ConditionalSession>([](const auto &) { return true; }, inner, unused));
    _router->get("/mw_test", tracing_handler());
    _router->compile();
    auto context = _router->route(_session, create_request());
    ASSERT_NE(context, nullptr);
    ASSERT_FALSE(context->is_completed());
    ASSERT_EQ(leaf->starts, 1);
    ASSERT_EQ(unused->starts, 0);

    context->cancel("leaf");
    context->cancel("leaf again");
    EXPECT_EQ(leaf->cancellations, 1);
    EXPECT_EQ(unused->cancellations, 0);
    EXPECT_TRUE(context->is_completed());
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(ConditionalMiddlewareTest, SynchronousChildCompletionKeepsTheNextCancellationTarget) {
    using PendingChild = conditional_cancellation_test::PendingChild;
    for (const bool next_is_conditional : {false, true}) {
        for (const bool throw_after_completion : {false, true}) {
            SCOPED_TRACE(::testing::Message() << "conditional next=" << next_is_conditional << ", throw=" << throw_after_completion);
            auto first = std::make_shared<PendingChild>(qb::http::AsyncTaskResult::CONTINUE, throw_after_completion);
            auto next  = std::make_shared<PendingChild>();
            _router    = std::make_unique<qb::http::Router<ConditionalSession>>();
            _router->use(qb::http::conditional_middleware<ConditionalSession>([](const auto &) { return true; }, first));
            if (next_is_conditional)
                _router->use(qb::http::conditional_middleware<ConditionalSession>([](const auto &) { return true; }, next));
            else
                _router->use(next);
            _router->get("/mw_test", tracing_handler());
            _router->compile();
            _session->reset();
            auto context = _router->route(_session, create_request());
            ASSERT_NE(context, nullptr);
            ASSERT_FALSE(context->is_completed());
            ASSERT_EQ(first->starts, 1);
            ASSERT_EQ(next->starts, 1);

            context->cancel("next task");
            context->cancel("next task again");
            EXPECT_EQ(first->cancellations, 0);
            EXPECT_EQ(next->cancellations, 1);
            context->complete(qb::http::AsyncTaskResult::CONTINUE);
            EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
            EXPECT_FALSE(_session->_final_handler_called);
        }
    }
}

TEST_F(ConditionalMiddlewareTest, ChildErrorKeepsTheErrorTaskCancellationTarget) {
    using PendingChild = conditional_cancellation_test::PendingChild;
    auto child         = std::make_shared<PendingChild>(qb::http::AsyncTaskResult::ERROR);
    auto error_task    = std::make_shared<PendingChild>();
    _router->use(qb::http::conditional_middleware<ConditionalSession>([](const auto &) { return true; }, child));
    _router->get("/mw_test", tracing_handler());
    _router->set_error_task_chain({std::make_shared<qb::http::MiddlewareTask<ConditionalSession>>(error_task)});
    _router->compile();
    auto context = _router->route(_session, create_request());
    ASSERT_NE(context, nullptr);
    ASSERT_FALSE(context->is_completed());
    ASSERT_EQ(child->starts, 1);
    ASSERT_EQ(error_task->starts, 1);
    EXPECT_EQ(context->get_processing_phase(), qb::http::Context<ConditionalSession>::ProcessingPhase::ERROR_CHAIN);

    context->cancel("error task");
    context->cancel("error task again");
    EXPECT_EQ(child->cancellations, 0);
    EXPECT_EQ(error_task->cancellations, 1);
    context->complete();
    EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(ConditionalMiddlewareTest, PredicateCancellationDoesNotStartAChild) {
    using PendingChild = conditional_cancellation_test::PendingChild;
    for (const bool nested : {false, true}) {
        SCOPED_TRACE(nested);
        auto child       = std::make_shared<PendingChild>();
        auto conditional = qb::http::conditional_middleware<ConditionalSession>(
            [](const auto &context) {
                context->cancel("predicate");
                return true;
            },
            child);
        _router = std::make_unique<qb::http::Router<ConditionalSession>>();
        if (nested)
            _router->use(qb::http::conditional_middleware<ConditionalSession>([](const auto &) { return true; }, conditional));
        else
            _router->use(conditional);
        _router->get("/mw_test", tracing_handler());
        _router->compile();
        _session->reset();
        auto context = _router->route(_session, create_request());
        ASSERT_NE(context, nullptr);
        EXPECT_TRUE(context->is_cancelled());
        EXPECT_TRUE(context->is_completed());
        EXPECT_EQ(child->starts, 0);
        EXPECT_EQ(child->cancellations, 0);
        EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
        EXPECT_FALSE(_session->_final_handler_called);
    }
}

TEST_F(ConditionalMiddlewareTest, PredicateCompletionDoesNotReplaceTheNextCancellationTarget) {
    using PendingChild = conditional_cancellation_test::PendingChild;
    for (const auto result : {qb::http::AsyncTaskResult::CONTINUE, qb::http::AsyncTaskResult::ERROR}) {
        SCOPED_TRACE(static_cast<int>(result));
        auto child = std::make_shared<PendingChild>();
        auto next  = std::make_shared<PendingChild>();
        _router    = std::make_unique<qb::http::Router<ConditionalSession>>();
        _router->use(qb::http::conditional_middleware<ConditionalSession>(
            [result](const auto &context) {
                context->complete(result);
                return true;
            },
            child));
        _router->use(next);
        _router->get("/mw_test", tracing_handler());
        _router->set_error_task_chain({std::make_shared<qb::http::MiddlewareTask<ConditionalSession>>(next)});
        _router->compile();
        _session->reset();
        auto context = _router->route(_session, create_request());
        ASSERT_NE(context, nullptr);
        ASSERT_FALSE(context->is_completed());
        ASSERT_EQ(child->starts, 0);
        ASSERT_EQ(next->starts, 1);

        context->cancel("next task after predicate");
        EXPECT_EQ(child->cancellations, 0);
        EXPECT_EQ(next->cancellations, 1);
        EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    }
}

TEST_F(ConditionalMiddlewareTest, SuppressedContextDoesNotNotifyTheSelectedChild) {
    using PendingChild = conditional_cancellation_test::PendingChild;
    auto child         = std::make_shared<PendingChild>();
    _router->use(qb::http::conditional_middleware<ConditionalSession>([](const auto &) { return true; }, child));
    _router->get("/mw_test", tracing_handler());
    _router->compile();
    auto context = _router->route(_session, create_request());
    ASSERT_NE(context, nullptr);
    ASSERT_FALSE(context->is_completed());
    ASSERT_EQ(child->starts, 1);

    context->suppress_response();
    context->cancel("suppressed");
    EXPECT_TRUE(context->is_completed());
    EXPECT_FALSE(context->is_cancelled());
    EXPECT_EQ(child->cancellations, 0);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(ConditionalMiddlewareTest, DeferredFinalizationDoesNotCancelACompletedChild) {
    using PendingChild = conditional_cancellation_test::PendingChild;
    auto child         = std::make_shared<PendingChild>();
    _router->use(qb::http::conditional_middleware<ConditionalSession>([](const auto &) { return true; }, child));
    _router->get("/mw_test", tracing_handler());
    _router->compile();
    auto context = _router->route(_session, create_request());
    ASSERT_NE(context, nullptr);
    ASSERT_FALSE(context->is_completed());
    ASSERT_EQ(child->starts, 1);

    {
        auto deferral = context->defer_finalization_scope();
        context->complete();
        ASSERT_FALSE(context->is_completed());
        context->cancel("finalization deferred");
        EXPECT_TRUE(context->is_cancelled());
        EXPECT_EQ(child->cancellations, 0);
    }
    EXPECT_TRUE(context->is_completed());
    EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
}

#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/conditional.h" // The adapted ConditionalMiddleware
#include "../routing/middleware.h" // For MiddlewareTask and IMiddleware if constructing children directly

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <sstream>

// --- Mock Session for ConditionalMiddleware Tests ---
struct MockConditionalSession {
    qb::http::Response _response;
    std::string _session_id_str = "conditional_test_session";
    std::ostringstream _trace;
    bool _final_handler_called = false;
    std::map<std::string, std::string> _request_headers_at_handler; // To check headers set by MW

    qb::http::Response &get_response_ref() { return _response; }

    MockConditionalSession &operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    void reset() {
        _response = qb::http::Response();
        _trace.str("");
        _trace.clear();
        _final_handler_called = false;
        _request_headers_at_handler.clear();
    }

    void trace(const std::string &point) {
        if (!_trace.str().empty()) _trace << ";";
        _trace << point;
    }

    std::string get_trace() const { return _trace.str(); }
};

// --- Helper Middleware for Conditional Tests (to act as child middleware) ---
class TracerMiddleware : public qb::http::IMiddleware<MockConditionalSession> {
public:
    TracerMiddleware(std::string id, std::string header_key = "", std::string header_value = "")
        : _id(std::move(id)), _header_key(std::move(header_key)), _header_value(std::move(header_value)) {
    }

    void process(std::shared_ptr<qb::http::Context<MockConditionalSession> > ctx) override {
        if (ctx->session()) {
            ctx->session()->trace(_id);
        }
        if (!_header_key.empty()) {
            ctx->request().set_header(_header_key, _header_value); // Modify request
        }
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }

    std::string name() const override { return _id; }

    void cancel() override {
    }

private:
    std::string _id;
    std::string _header_key;
    std::string _header_value;
};

// --- Test Fixture for ConditionalMiddleware ---
class ConditionalMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockConditionalSession> _session;
    std::unique_ptr<qb::http::Router<MockConditionalSession> > _router;
    // TaskExecutor not typically needed for testing ConditionalMiddleware directly,
    // unless the predicate or child middlewares are async.

    void SetUp() override {
        _session = std::make_shared<MockConditionalSession>();
        _router = std::make_unique<qb::http::Router<MockConditionalSession> >();
    }

    qb::http::Request create_request(const std::string &target_path = "/test") {
        qb::http::Request req;
        req.method() = qb::http::method::GET;
        try {
            req.uri() = qb::io::uri(target_path);
        } catch (const std::exception &e) {
            ADD_FAILURE() << "URI parse failure: " << target_path << " (" << e.what() << ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        return req;
    }

    qb::http::RouteHandlerFn<MockConditionalSession> final_handler(const std::string &id = "FinalHandler") {
        return [this, id](std::shared_ptr<qb::http::Context<MockConditionalSession> > ctx) {
            if (_session) {
                _session->trace(id);
                _session->_final_handler_called = true;
                for (const auto &entry: ctx->request().headers()) {
                    if (!entry.second.empty()) {
                        // entry.second is std::vector<String>
                        std::string key = std::string(entry.first);
                        std::transform(key.begin(), key.end(), key.begin(),
                                       [](unsigned char c) { return std::tolower(c); });
                        _session->_request_headers_at_handler[key] = std::string(entry.second.front());
                    }
                }
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        };
    }

    void configure_and_run(std::shared_ptr<qb::http::ConditionalMiddleware<MockConditionalSession> > cond_mw,
                           qb::http::Request request) {
        _router->use(cond_mw);
        _router->get("/test", final_handler());
        _router->compile();
        _session->reset();
        _router->route(_session, std::move(request));
    }
};

// --- Test Cases ---

TEST_F(ConditionalMiddlewareTest, ConditionTrueExecutesIfMiddleware) {
    auto predicate = [](const std::shared_ptr<qb::http::Context<MockConditionalSession> > &ctx) -> bool {
        return ctx->request().uri().path() == "/test";
    };
    auto if_mw = std::make_shared<TracerMiddleware>("IfMiddleware");
    auto cond_mw = qb::http::conditional_middleware<MockConditionalSession>(predicate, if_mw);

    configure_and_run(cond_mw, create_request("/test"));

    EXPECT_EQ(_session->get_trace(), "IfMiddleware;FinalHandler");
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(ConditionalMiddlewareTest, ConditionFalseWithElseExecutesElseMiddleware) {
    auto predicate = [](const std::shared_ptr<qb::http::Context<MockConditionalSession> > &ctx) -> bool {
        return ctx->request().has_header("X-Execute-If");
    };
    auto if_mw = std::make_shared<TracerMiddleware>("IfMiddleware_NeverRuns");
    auto else_mw = std::make_shared<TracerMiddleware>("ElseMiddleware");
    auto cond_mw = qb::http::conditional_middleware<MockConditionalSession>(predicate, if_mw, else_mw);

    configure_and_run(cond_mw, create_request("/test")); // No "X-Execute-If" header

    EXPECT_EQ(_session->get_trace(), "ElseMiddleware;FinalHandler");
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(ConditionalMiddlewareTest, ConditionFalseWithoutElseContinues) {
    bool predicate_called = false;
    auto predicate = [&predicate_called](const auto & /*ctx*/) -> bool {
        predicate_called = true;
        return false;
    };
    auto if_mw = std::make_shared<TracerMiddleware>("IfMiddleware_NeverRuns");
    // No else middleware provided
    auto cond_mw = qb::http::conditional_middleware<MockConditionalSession>(predicate, if_mw);

    configure_and_run(cond_mw, create_request("/test"));

    EXPECT_EQ(_session->get_trace(), "FinalHandler"); // Only final handler should run
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_TRUE(predicate_called);
}

TEST_F(ConditionalMiddlewareTest, ContextManipulationInPredicateAndChild) {
    auto predicate = [](const std::shared_ptr<qb::http::Context<MockConditionalSession> > &ctx) -> bool {
        ctx->set("predicate_decision", std::string("took_if_branch"));
        return true;
    };
    auto if_mw = std::make_shared<TracerMiddleware>("IfMiddlewareSetsHeader", "X-If-Action", "Performed");
    auto cond_mw = qb::http::conditional_middleware<MockConditionalSession>(predicate, if_mw);

    // Modify success_handler to check context data and header
    _router = std::make_unique<qb::http::Router<MockConditionalSession> >(); // Reset router for this specific handler
    _router->use(cond_mw);
    _router->get("/test", [this](std::shared_ptr<qb::http::Context<MockConditionalSession> > ctx) {
        _session->trace("FinalHandlerChecksContext");
        _session->_final_handler_called = true;
        auto decision_opt = ctx->template get<std::string>("predicate_decision");
        ASSERT_TRUE(decision_opt.has_value());
        EXPECT_EQ(*decision_opt, "took_if_branch");
        EXPECT_EQ(std::string(ctx->request().header("X-If-Action")), "Performed");
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();
    _session->reset();
    _router->route(_session, create_request("/test"));

    EXPECT_EQ(_session->get_trace(), "IfMiddlewareSetsHeader;FinalHandlerChecksContext");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(ConditionalMiddlewareTest, NestedConditionalMiddleware) {
    // Outer: if header X-Outer, run inner_cond_mw, else run outer_else_mw
    auto outer_predicate = [](const auto &ctx) { return ctx->request().has_header("X-Outer"); };
    auto outer_else_mw = std::make_shared<TracerMiddleware>("OuterElse");

    // Inner: if header X-Inner, run inner_if_mw, else run inner_else_mw
    auto inner_predicate = [](const auto &ctx) { return ctx->request().has_header("X-Inner"); };
    auto inner_if_mw = std::make_shared<TracerMiddleware>("InnerIf");
    auto inner_else_mw = std::make_shared<TracerMiddleware>("InnerElse");
    auto inner_cond_mw = qb::http::conditional_middleware<MockConditionalSession>(
        inner_predicate, inner_if_mw, inner_else_mw, "InnerConditional");

    auto outer_cond_mw = qb::http::conditional_middleware<MockConditionalSession>(
        outer_predicate, inner_cond_mw, outer_else_mw, "OuterConditional");

    // Scenario 1: Outer=true, Inner=true  => InnerIf
    _router = std::make_unique<qb::http::Router<MockConditionalSession> >(); // Reset router
    auto req1 = create_request("/test");
    req1.set_header("X-Outer", "true");
    req1.set_header("X-Inner", "true");
    configure_and_run(outer_cond_mw, std::move(req1));
    EXPECT_EQ(_session->get_trace(), "InnerIf;FinalHandler");

    // Scenario 2: Outer=true, Inner=false => InnerElse
    _router = std::make_unique<qb::http::Router<MockConditionalSession> >(); // Reset router
    auto req2 = create_request("/test");
    req2.set_header("X-Outer", "true");
    configure_and_run(outer_cond_mw, std::move(req2));
    EXPECT_EQ(_session->get_trace(), "InnerElse;FinalHandler");

    // Scenario 3: Outer=false             => OuterElse
    _router = std::make_unique<qb::http::Router<MockConditionalSession> >(); // Reset router
    auto req3 = create_request("/test");
    configure_and_run(outer_cond_mw, std::move(req3));
    EXPECT_EQ(_session->get_trace(), "OuterElse;FinalHandler");
}

class CompletingTracerMiddleware : public qb::http::IMiddleware<MockConditionalSession> {
public:
    CompletingTracerMiddleware(std::string id) : _id(std::move(id)) {
    }

    void process(std::shared_ptr<qb::http::Context<MockConditionalSession> > ctx) override {
        if (ctx->session()) ctx->session()->trace(_id);
        ctx->response().status() = qb::http::status::NO_CONTENT; // Indicate it did something
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE); // Key part: completes the chain
    }

    std::string name() const override { return _id; }

    void cancel() override {
    }

private:
    std::string _id;
};

TEST_F(ConditionalMiddlewareTest, ConditionTrueIfCompletes) {
    auto predicate = [](const auto & /*ctx*/) { return true; };
    auto if_mw = std::make_shared<CompletingTracerMiddleware>("IfMiddlewareCompletes");
    auto cond_mw = qb::http::conditional_middleware<MockConditionalSession>(predicate, if_mw);

    configure_and_run(cond_mw, create_request("/test"));

    EXPECT_EQ(_session->get_trace(), "IfMiddlewareCompletes");
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::NO_CONTENT);
}

TEST_F(ConditionalMiddlewareTest, ConditionFalseElseCompletes) {
    auto predicate = [](const auto & /*ctx*/) { return false; };
    auto if_mw = std::make_shared<TracerMiddleware>("IfMiddleware_NeverRuns"); // Standard tracer
    auto else_mw = std::make_shared<CompletingTracerMiddleware>("ElseMiddlewareCompletes");
    auto cond_mw = qb::http::conditional_middleware<MockConditionalSession>(predicate, if_mw, else_mw);

    configure_and_run(cond_mw, create_request("/test"));

    EXPECT_EQ(_session->get_trace(), "ElseMiddlewareCompletes");
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::NO_CONTENT);
}

TEST_F(ConditionalMiddlewareTest, ChainedConditionalsExecuteSequentially) {
    // Conditional MW 1: if path is /test, add header X-Chain1-Passed
    auto pred1 = [](const auto &ctx) { return ctx->request().uri().path() == "/test"; };
    auto if_mw1 = std::make_shared<TracerMiddleware>("Chain1If", "X-Chain1-Passed", "yes");
    auto cond_mw1 = qb::http::conditional_middleware<MockConditionalSession>(pred1, if_mw1, nullptr, "CondChain1");

    // Conditional MW 2: if header X-Chain1-Passed is yes, trace Chain2If
    auto pred2 = [](const auto &ctx) { return std::string(ctx->request().header("X-Chain1-Passed")) == "yes"; };
    auto if_mw2 = std::make_shared<TracerMiddleware>("Chain2If");
    auto cond_mw2 = qb::http::conditional_middleware<MockConditionalSession>(pred2, if_mw2, nullptr, "CondChain2");

    _router->use(cond_mw1);
    _router->use(cond_mw2);
    _router->get("/test", final_handler());
    _router->compile();

    _session->reset();
    _router->route(_session, create_request("/test"));

    EXPECT_EQ(_session->get_trace(), "Chain1If;Chain2If;FinalHandler");
    EXPECT_TRUE(_session->_final_handler_called);
    std::string lower_case_header_key = "X-Chain1-Passed";
    std::transform(lower_case_header_key.begin(), lower_case_header_key.end(), lower_case_header_key.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    EXPECT_EQ(_session->_request_headers_at_handler[lower_case_header_key], "yes");
}

TEST_F(ConditionalMiddlewareTest, PredicateCalledOnce) {
    int predicate_call_count = 0;
    auto predicate = [&](const auto & /*ctx*/) -> bool {
        predicate_call_count++;
        return true;
    };
    auto if_mw = std::make_shared<TracerMiddleware>("IfMiddlewareForPredicateCount");
    auto cond_mw = qb::http::conditional_middleware<MockConditionalSession>(predicate, if_mw);

    // Scenario 1: Predicate true, ensure it's called once
    _router = std::make_unique<qb::http::Router<MockConditionalSession> >(); // Reset router
    configure_and_run(cond_mw, create_request("/test"));
    EXPECT_EQ(predicate_call_count, 1);
    EXPECT_EQ(_session->get_trace(), "IfMiddlewareForPredicateCount;FinalHandler");

    // Scenario 2: Run again to ensure count is per-request if middleware is reused (it should be, state is external)
    // For this, we need to reset count and session trace before the second run.
    predicate_call_count = 0;
    // _session is reset by configure_and_run
    // configure_and_run re-adds cond_mw to a new router if _router->use is called again,
    // but here we use the same cond_mw instance for a new request on the *same* configured router from previous call.
    // So, let's call _router->route directly to simulate a new request to an already configured router.
    // No, configure_and_run always does _router->use(), then compiles.
    // To test reuse on same config, we'd need a different setup. Let's keep it simple:
    // Test that when a new request comes to a *freshly* configured router with this cond_mw, it's still 1.
    _router = std::make_unique<qb::http::Router<MockConditionalSession> >(); // Reset router for a clean run
    configure_and_run(cond_mw, create_request("/test"));
    EXPECT_EQ(predicate_call_count, 1) << "Predicate should be called once per request processing through it.";
}

TEST_F(ConditionalMiddlewareTest, PredicateThrowsException) {
    auto predicate = [](const auto & /*ctx*/) -> bool {
        throw std::runtime_error("Predicate failed!");
    };
    auto if_mw = std::make_shared<TracerMiddleware>("IfMiddleware_NeverRunsDueToPredicateError");
    auto cond_mw = qb::http::conditional_middleware<MockConditionalSession>(predicate, if_mw);

    // We expect the exception to propagate or be handled by the router/context, leading to an error response.
    // The exact error code might depend on the global error handling of the qb::http::Router.
    // For now, we'll check that the final handler isn't called and the status isn't OK.
    // A more robust test would check for a specific error status if the router guarantees one.

    bool exception_caught_by_router = false;
    try {
        configure_and_run(cond_mw, create_request("/test"));
        // If configure_and_run completes without throwing, then the router must have caught it.
        exception_caught_by_router = true;
    } catch (const std::runtime_error &e) {
        // If it propagates all the way here, that's one outcome.
        EXPECT_STREQ(e.what(), "Predicate failed!");
    } catch (...) {
        FAIL() << "Unexpected exception type caught.";
    }

    if (exception_caught_by_router) {
        EXPECT_NE(_session->_response.status(), qb::http::status::OK);
        // Potentially check for 500 or other specific error code if qb::http::Router defines behavior.
        // For example: EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    }
    EXPECT_FALSE(_session->_final_handler_called);
}

class ThrowingTracerMiddleware : public qb::http::IMiddleware<MockConditionalSession> {
public:
    ThrowingTracerMiddleware(std::string id, std::string message) : _id(std::move(id)), _message(std::move(message)) {
    }

    void process(std::shared_ptr<qb::http::Context<MockConditionalSession> > ctx) override {
        if (ctx->session()) ctx->session()->trace(_id);
        throw std::runtime_error(_message);
    }

    std::string name() const override { return _id; }

    void cancel() override {
    }

private:
    std::string _id;
    std::string _message;
};

TEST_F(ConditionalMiddlewareTest, IfMiddlewareThrowsException) {
    auto predicate = [](const auto & /*ctx*/) { return true; };
    auto if_mw = std::make_shared<ThrowingTracerMiddleware>("IfMiddlewareThrows", "If child failed");
    auto cond_mw = qb::http::conditional_middleware<MockConditionalSession>(predicate, if_mw);

    bool exception_caught_by_router = false;
    try {
        configure_and_run(cond_mw, create_request("/test"));
        exception_caught_by_router = true;
    } catch (const std::runtime_error &e) {
        EXPECT_STREQ(e.what(), "If child failed");
    } catch (...) {
        FAIL() << "Unexpected exception type caught in IfMiddlewareThrowsException.";
    }

    if (exception_caught_by_router) {
        EXPECT_NE(_session->_response.status(), qb::http::status::OK);
    }
    EXPECT_EQ(_session->get_trace(), "IfMiddlewareThrows"); // It should at least trace before throwing
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(ConditionalMiddlewareTest, ElseMiddlewareThrowsException) {
    auto predicate = [](const auto & /*ctx*/) { return false; };
    auto if_mw = std::make_shared<TracerMiddleware>("IfMiddleware_NeverRuns");
    auto else_mw = std::make_shared<ThrowingTracerMiddleware>("ElseMiddlewareThrows", "Else child failed");
    auto cond_mw = qb::http::conditional_middleware<MockConditionalSession>(predicate, if_mw, else_mw);

    bool exception_caught_by_router = false;
    try {
        configure_and_run(cond_mw, create_request("/test"));
        exception_caught_by_router = true;
    } catch (const std::runtime_error &e) {
        EXPECT_STREQ(e.what(), "Else child failed");
    } catch (...) {
        FAIL() << "Unexpected exception type caught in ElseMiddlewareThrowsException.";
    }

    if (exception_caught_by_router) {
        EXPECT_NE(_session->_response.status(), qb::http::status::OK);
    }
    EXPECT_EQ(_session->get_trace(), "ElseMiddlewareThrows");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(ConditionalMiddlewareTest, ThrowsOnNullIfMiddleware) {
    auto predicate = [](const auto & /*ctx*/) { return true; };
    std::shared_ptr<qb::http::IMiddleware<MockConditionalSession> > null_if_mw = nullptr;
    std::shared_ptr<qb::http::IMiddleware<MockConditionalSession> > dummy_else_mw = std::make_shared<
        TracerMiddleware>("DummyElse");

    EXPECT_THROW(
        (void)qb::http::conditional_middleware<MockConditionalSession>(predicate, null_if_mw, dummy_else_mw),
        std::invalid_argument
    );

    // Also test with constructor directly if desired, though factory is primary API
    // EXPECT_THROW(
    //     auto mw = Conditional/÷÷÷÷≥>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.Middleware<MockConditionalSession>(predicate, null_if_mw, dummy_else_mw),
    //     std::invalid_argument÷÷÷≥>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>..........................................;;;;;;//////\"'''''''''''''''''''''''''''''''''''''']'[';]"
    // );

    // Test with null predicate
    std::shared_ptr<qb::http::IMiddleware<MockConditionalSession> > valid_if_mw = std::make_shared<
        TracerMiddleware>("ValidIf");
    qb::http::ConditionalMiddleware<MockConditionalSession>::Predicate null_predicate = nullptr;
    EXPECT_THROW(
        (void)qb::http::conditional_middleware<MockConditionalSession>(null_predicate, valid_if_mw, dummy_else_mw),
        std::invalid_argument
    );
}

// TODO: Add more tests for ConditionalMiddleware:
// - FactoryFunction (already used implicitly by qb::http::conditional_middleware)
// - ResultPropagation (how results from child middlewares affect overall flow - covered by basic tests)
// - ComplexPredicate (predicates that examine request body, etc. - depends on predicate capabilities)
// - ChainedConditionals (multiple conditional middlewares in sequence)
// - PredicateStability (predicate is not called multiple times unnecessarily)

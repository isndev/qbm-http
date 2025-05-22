#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/error_handling.h" // The adapted ErrorHandlingMiddleware
#include "../routing/middleware.h" // For MiddlewareTask and IMiddleware

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <sstream>

// --- Mock Session for ErrorHandlingMiddleware Tests ---
struct MockErrorHandlingSession {
    qb::http::Response _response;
    std::string _session_id_str = "error_handling_test_session";
    std::ostringstream _trace;
    bool _final_handler_called_flag = false; // Renamed to avoid conflict with fixture member
    std::string _last_error_message_handled_by_generic;

    qb::http::Response &get_response_ref() { return _response; }

    MockErrorHandlingSession &operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    void reset() {
        _response = qb::http::Response();
        _trace.str("");
        _trace.clear();
        _final_handler_called_flag = false;
        _last_error_message_handled_by_generic.clear();
    }

    void trace(const std::string &point) {
        if (!_trace.str().empty()) _trace << ";";
        _trace << point;
    }

    std::string get_trace() const { return _trace.str(); }
};

// --- Helper Task that can signal an error ---
class ErrorSignalerTask : public qb::http::IMiddleware<MockErrorHandlingSession> {
public:
    ErrorSignalerTask(std::string id, qb::http::status status_to_set_before_error, std::string msg = "")
        : _id(std::move(id)), _status_to_set(status_to_set_before_error), _error_message(std::move(msg)) {
    }

    void process(std::shared_ptr<qb::http::Context<MockErrorHandlingSession> > ctx) override {
        if (ctx->session()) ctx->session()->trace(_id + "_triggered");
        ctx->response().status() = _status_to_set;
        if (!_error_message.empty()) {
            ctx->response().body() = "ErrorTrigger: " + _error_message;
            ctx->set("__error_message", _error_message); // For generic handler test
        }
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
    }

    std::string name() const override { return _id; }

    void cancel() override {
    }

private:
    std::string _id;
    qb::http::status _status_to_set;
    std::string _error_message;
};

// --- Test Fixture for ErrorHandlingMiddleware ---
class ErrorHandlingMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockErrorHandlingSession> _session;
    std::unique_ptr<qb::http::Router<MockErrorHandlingSession> > _router;
    std::shared_ptr<qb::http::ErrorHandlingMiddleware<MockErrorHandlingSession> > _error_mw;

    void SetUp() override {
        _session = std::make_shared<MockErrorHandlingSession>();
        _router = std::make_unique<qb::http::Router<MockErrorHandlingSession> >();
        _error_mw = qb::http::error_handling_middleware<MockErrorHandlingSession>("TestErrorMW");
    }

    qb::http::Request create_request(const std::string &target_path = "/error_trigger") {
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

    // Dummy handler that should not be called if error occurs before it
    qb::http::RouteHandlerFn<MockErrorHandlingSession> normal_route_handler() {
        return [this](std::shared_ptr<qb::http::Context<MockErrorHandlingSession> > ctx) {
            if (_session) _session->trace("NormalRouteHandlerCalled");
            _session->_final_handler_called_flag = true;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "Normal handler reached successfully";
            ctx->complete();
        };
    }

    void configure_router_and_make_request(
        std::shared_ptr<qb::http::IMiddleware<MockErrorHandlingSession> > error_trigger_task,
        const std::string &path = "/error_trigger") {
        _router->use(error_trigger_task); // This task will signal ERROR
        _router->get(path, normal_route_handler()); // This handler should be bypassed

        // Set the error handling middleware as the error chain for the router
        std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession> > > error_chain;
        error_chain.push_back(
            std::make_shared<qb::http::MiddlewareTask<MockErrorHandlingSession> >(_error_mw, _error_mw->name()));
        _router->set_error_task_chain(error_chain);

        _router->compile();
        _session->reset();
        _router->route(_session, create_request(path));
    }
};

// --- Test Cases ---

TEST_F(ErrorHandlingMiddlewareTest, SpecificStatusCodeHandler) {
    bool custom_handler_called = false;
    _error_mw->on_status(qb::http::status::BAD_GATEWAY,
                         [&custom_handler_called, this](
                     std::shared_ptr<qb::http::Context<MockErrorHandlingSession> > ctx) {
                             custom_handler_called = true;
                             if (_session) _session->trace("CustomBadGatewayHandler");
                             ctx->response().status() = qb::http::status::BAD_GATEWAY; // Keep or change
                             ctx->response().body() = "Handled specifically by BadGateway handler.";
                             // No ctx->complete() here; ErrorHandlingMiddleware::handle does it.
                         });

    auto trigger_task = std::make_shared<ErrorSignalerTask>("ErrorTrigger502", qb::http::status::BAD_GATEWAY);
    configure_router_and_make_request(trigger_task);

    EXPECT_TRUE(custom_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled specifically by BadGateway handler.");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger502_triggered;CustomBadGatewayHandler");
    EXPECT_FALSE(_session->_final_handler_called_flag); // Normal handler should not be called
}

TEST_F(ErrorHandlingMiddlewareTest, StatusCodeRangeHandler) {
    bool custom_4xx_handler_called = false;
    _error_mw->on_status_range(qb::http::status::BAD_REQUEST, qb::http::status::PAYMENT_REQUIRED,
                               [&custom_4xx_handler_called, this](
                           std::shared_ptr<qb::http::Context<MockErrorHandlingSession> > ctx) {
                                   custom_4xx_handler_called = true;
                                   if (_session) _session->trace("Custom4xxRangeHandler");
                                   ctx->response().body() = "Handled by 4xx range: Original status " + std::to_string(
                                                                static_cast<int>(ctx->response().status()));
                                   ctx->response().status() = qb::http::status::FORBIDDEN; // Change it
                               });

    auto trigger_task = std::make_shared<ErrorSignalerTask>("ErrorTrigger401", qb::http::status::UNAUTHORIZED);
    configure_router_and_make_request(trigger_task);

    EXPECT_TRUE(custom_4xx_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled by 4xx range: Original status 401");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger401_triggered;Custom4xxRangeHandler");
}

TEST_F(ErrorHandlingMiddlewareTest, GenericErrorHandler) {
    bool generic_handler_called = false;
    std::string received_message;
    _error_mw->on_any_error(
        [&generic_handler_called, &received_message, this](
    std::shared_ptr<qb::http::Context<MockErrorHandlingSession> > ctx, const std::string &error_message) {
            generic_handler_called = true;
            received_message = error_message;
            if (_session) _session->trace("GenericErrorHandler");
            ctx->response().status() = qb::http::status::NOT_IMPLEMENTED;
            ctx->response().body() = "Generic handler caught: " + error_message;
        });

    auto trigger_task = std::make_shared<ErrorSignalerTask>("ErrorTrigger500", qb::http::status::INTERNAL_SERVER_ERROR,
                                                            "Specific details for generic handler");
    configure_router_and_make_request(trigger_task);

    EXPECT_TRUE(generic_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_IMPLEMENTED);
    EXPECT_EQ(_session->_response.body().as<std::string>(),
              "Generic handler caught: Specific details for generic handler");
    EXPECT_EQ(received_message, "Specific details for generic handler");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger500_triggered;GenericErrorHandler");
}

TEST_F(ErrorHandlingMiddlewareTest, NoMatchingErrorHandlerUsesDefaultBehavior) {
    // No specific handlers configured on _error_mw for HTTP_STATUS_NOT_ACCEPTABLE
    auto trigger_task = std::make_shared<ErrorSignalerTask>("ErrorTrigger406", qb::http::status::NOT_ACCEPTABLE,
                                                            "No handler for this");
    configure_router_and_make_request(trigger_task);

    // ErrorHandlingMiddleware still calls complete(COMPLETE). The response state would be what ErrorSignalerTask set.
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_ACCEPTABLE);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "ErrorTrigger: No handler for this");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger406_triggered"); // Only the trigger traces
}

TEST_F(ErrorHandlingMiddlewareTest, HandlerPrioritySpecificOverGeneric) {
    bool specific_handler_called = false;
    bool generic_handler_called = false;

    _error_mw->on_status(qb::http::status::SERVICE_UNAVAILABLE,
                         [&specific_handler_called, this](auto ctx) {
                             specific_handler_called = true;
                             if (_session) _session->trace("Specific503Handler");
                             ctx->response().body() = "Handled by specific 503.";
                         });
    _error_mw->on_any_error([&generic_handler_called](auto /*ctx*/, const auto & /*msg*/) {
        generic_handler_called = true;
    });

    auto trigger_task = std::make_shared<ErrorSignalerTask>("ErrorTrigger503", qb::http::status::SERVICE_UNAVAILABLE);
    configure_router_and_make_request(trigger_task);

    EXPECT_TRUE(specific_handler_called);
    EXPECT_FALSE(generic_handler_called);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled by specific 503.");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger503_triggered;Specific503Handler");
}

TEST_F(ErrorHandlingMiddlewareTest, RangeHandlerPriorityOverGeneric) {
    bool range_handler_called = false;
    bool generic_handler_called = false;

    _error_mw->on_status_range(qb::http::status::INTERNAL_SERVER_ERROR, qb::http::status::BAD_GATEWAY, // 500-502
                               [&range_handler_called, this](auto ctx) {
                                   range_handler_called = true;
                                   if (_session) _session->trace("Range500-502Handler");
                                   ctx->response().body() = "Handled by 500-502 range.";
                                   ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                               });

    _error_mw->on_any_error(
        [&generic_handler_called, this](auto /*ctx*/, const auto & /*msg*/) {
            generic_handler_called = true;
            if (_session) _session->trace("GenericHandler");
        });

    auto trigger_task = std::make_shared<ErrorSignalerTask>("ErrorTrigger501", qb::http::status::NOT_IMPLEMENTED);
    // 501 is in range
    configure_router_and_make_request(trigger_task);

    EXPECT_TRUE(range_handler_called);
    EXPECT_FALSE(generic_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled by 500-502 range.");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger501_triggered;Range500-502Handler");
}

TEST_F(ErrorHandlingMiddlewareTest, MultipleErrorHandlersInChain) {
    auto error_mw1 = qb::http::error_handling_middleware<MockErrorHandlingSession>("ErrorMW1");
    auto error_mw2 = qb::http::error_handling_middleware<MockErrorHandlingSession>("ErrorMW2");
    bool handler1_called = false;
    bool handler2_called = false;

    error_mw1->on_status(qb::http::status::INTERNAL_SERVER_ERROR,
                         [&handler1_called, this](auto ctx) {
                             handler1_called = true;
                             if (_session) _session->trace("HandlerFromMW1");
                             ctx->response().body() = "Handled by MW1";
                             ctx->response().status() = qb::http::status::OK; // Change status
                         });

    error_mw2->on_status(qb::http::status::INTERNAL_SERVER_ERROR,
                         [&handler2_called, this](auto ctx) {
                             handler2_called = true;
                             if (_session) _session->trace("HandlerFromMW2");
                             ctx->response().body() = "Handled by MW2";
                         });
    error_mw2->on_any_error( // Add a generic too to mw2 to see if it's hit
        [&handler2_called, this](auto ctx, const auto & /*msg*/) {
            // Named ctx
            handler2_called = true; // If this is called, something is wrong with mw1 completion
            if (_session) _session->trace("GenericHandlerFromMW2");
            ctx->response().body() = "Generic in MW2";
        });


    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession> > > error_chain;
    error_chain.push_back(
        std::make_shared<qb::http::MiddlewareTask<MockErrorHandlingSession> >(error_mw1, error_mw1->name()));
    error_chain.push_back(
        std::make_shared<qb::http::MiddlewareTask<MockErrorHandlingSession> >(error_mw2, error_mw2->name()));

    _router = std::make_unique<qb::http::Router<MockErrorHandlingSession> >(); // New router for this test
    _router->set_error_task_chain(error_chain);

    auto trigger_task = std::make_shared<ErrorSignalerTask>("ErrorTrigger500", qb::http::status::INTERNAL_SERVER_ERROR);
    _router->use(trigger_task);
    _router->get("/error_trigger", normal_route_handler());
    _router->compile();

    _session->reset();
    _router->route(_session, create_request("/error_trigger"));

    EXPECT_TRUE(handler1_called);
    EXPECT_FALSE(handler2_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled by MW1");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger500_triggered;HandlerFromMW1");
}

TEST_F(ErrorHandlingMiddlewareTest, FactoryFunctionCreatesInstance) {
    auto factory_mw = qb::http::error_handling_middleware<MockErrorHandlingSession>("FactoryTestErrorMW");
    ASSERT_NE(factory_mw, nullptr);
    EXPECT_EQ(factory_mw->name(), "FactoryTestErrorMW");

    // Verify it works by configuring a handler and routing an error to it
    bool factory_handler_called = false;
    factory_mw->on_status(qb::http::status::NOT_FOUND,
                          [&factory_handler_called, this](auto ctx) {
                              factory_handler_called = true;
                              if (_session) _session->trace("FactoryMWHandler404");
                              ctx->response().body() = "Handled by factory MW (404)";
                              ctx->response().status() = qb::http::status::OK;
                          });

    auto local_router = std::make_unique<qb::http::Router<MockErrorHandlingSession> >();
    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession> > > error_chain;
    error_chain.push_back(
        std::make_shared<qb::http::MiddlewareTask<MockErrorHandlingSession> >(factory_mw, factory_mw->name()));
    local_router->set_error_task_chain(error_chain);

    auto trigger_task = std::make_shared<ErrorSignalerTask>("ErrorTrigger404", qb::http::status::NOT_FOUND);
    local_router->use(trigger_task);
    local_router->get("/error_trigger_404", normal_route_handler()); // Should not be called
    local_router->compile();

    _session->reset(); // Use the fixture's session
    local_router->route(_session, create_request("/error_trigger_404"));

    EXPECT_TRUE(factory_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled by factory MW (404)");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger404_triggered;FactoryMWHandler404");
}

TEST_F(ErrorHandlingMiddlewareTest, SpecificHandlerPriorityOverRange) {
    bool specific_handler_called = false;
    bool range_handler_called = false;

    _error_mw->on_status(qb::http::status::BAD_GATEWAY, // 502
                         [&specific_handler_called, this](auto ctx) {
                             specific_handler_called = true;
                             if (_session) _session->trace("Specific502Handler");
                             ctx->response().body() = "Handled by specific 502 handler.";
                         });

    _error_mw->on_status_range(qb::http::status::INTERNAL_SERVER_ERROR, qb::http::status::SERVICE_UNAVAILABLE,
                               // 500-503
                               [&range_handler_called, this](auto ctx) {
                                   range_handler_called = true;
                                   if (_session) _session->trace("Range500-503Handler");
                                   ctx->response().body() = "Handled by 500-503 range.";
                               });

    auto trigger_task = std::make_shared<ErrorSignalerTask>("ErrorTrigger502", qb::http::status::BAD_GATEWAY);
    configure_router_and_make_request(trigger_task);

    EXPECT_TRUE(specific_handler_called);
    EXPECT_FALSE(range_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_GATEWAY); // Original status is preserved by default
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled by specific 502 handler.");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger502_triggered;Specific502Handler");
}

TEST_F(ErrorHandlingMiddlewareTest, FirstMatchingRangeHandlerWins) {
    bool handler_A_called = false;
    bool handler_B_called = false;

    // Handler A: Range 500-501
    _error_mw->on_status_range(qb::http::status::INTERNAL_SERVER_ERROR, qb::http::status::NOT_IMPLEMENTED,
                               [&handler_A_called, this](auto ctx) {
                                   handler_A_called = true;
                                   if (_session) _session->trace("HandlerA_500-501");
                                   ctx->response().body() = "Handled by A (500-501).";
                               });

    // Handler B: Range 501-502 (overlaps with A on 501)
    _error_mw->on_status_range(qb::http::status::NOT_IMPLEMENTED, qb::http::status::BAD_GATEWAY,
                               [&handler_B_called, this](auto ctx) {
                                   handler_B_called = true;
                                   if (_session) _session->trace("HandlerB_501-502");
                                   ctx->response().body() = "Handled by B (501-502).";
                               });

    // Trigger an error for status 501 (HTTP_STATUS_NOT_IMPLEMENTED)
    auto trigger_task = std::make_shared<ErrorSignalerTask>("ErrorTrigger501", qb::http::status::NOT_IMPLEMENTED);
    configure_router_and_make_request(trigger_task);

    EXPECT_TRUE(handler_A_called); // Handler A was defined first and matches
    EXPECT_FALSE(handler_B_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_IMPLEMENTED);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled by A (500-501).");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger501_triggered;HandlerA_500-501");
}

TEST_F(ErrorHandlingMiddlewareTest, ErrorHandlerCanModifyResponse) {
    bool handler_called = false;
    _error_mw->on_status(qb::http::status::NOT_FOUND, // 404
                         [&handler_called, this](auto ctx) {
                             handler_called = true;
                             if (_session) _session->trace("HandlerModifiesResponse404");
                             ctx->response().status() = qb::http::status::EXPECTATION_FAILED; // Change to 417
                             ctx->response().body() = "This was a 404, now it is a 417 with custom message.";
                             ctx->response().set_header("X-Error-Handled", "True");
                         });

    auto trigger_task = std::make_shared<ErrorSignalerTask>("ErrorTrigger404", qb::http::status::NOT_FOUND,
                                                            "Original 404 body");
    configure_router_and_make_request(trigger_task);

    EXPECT_TRUE(handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::EXPECTATION_FAILED);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "This was a 404, now it is a 417 with custom message.");
    EXPECT_EQ(std::string(_session->_response.header("X-Error-Handled")), "True");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger404_triggered;HandlerModifiesResponse404");
}

TEST_F(ErrorHandlingMiddlewareTest, GenericHandlerReceivesDefaultMessageWhenContextUnset) {
    bool generic_handler_called = false;
    std::string received_message_in_handler;

    _error_mw->on_any_error(
        [&generic_handler_called, &received_message_in_handler, this](auto ctx, const std::string &error_message) {
            generic_handler_called = true;
            received_message_in_handler = error_message;
            if (_session) _session->trace("GenericHandlerDefaultMsg");
            ctx->response().body() = "Generic caught: " + error_message;
            // Keep original status or set a new one
            ctx->response().status() = qb::http::status::IM_A_TEAPOT;
        });

    // ErrorSignalerTask here does NOT set "__error_message" in context, or sets it empty.
    // We are testing the default message generation.
    auto trigger_task = std::make_shared<ErrorSignalerTask>(
        "ErrorTrigger403NoCtxMsg",
        qb::http::status::FORBIDDEN,
        "" // Empty message from signaler, so __error_message won't be set meaningfully if signaler sets it based on this.
    );
    // To be sure __error_message is not set from signaler, let's ensure ErrorSignalerTask only uses its msg for body.
    // The generic handler in ErrorHandlingMiddleware should then generate its default.

    configure_router_and_make_request(trigger_task);

    EXPECT_TRUE(generic_handler_called);
    std::string expected_default_message = "Error encountered: status " + std::to_string(
                                               static_cast<int>(qb::http::status::FORBIDDEN));
    EXPECT_EQ(received_message_in_handler, expected_default_message);
    EXPECT_EQ(_session->_response.status(), qb::http::status::IM_A_TEAPOT);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Generic caught: " + expected_default_message);
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger403NoCtxMsg_triggered;GenericHandlerDefaultMsg");
}

TEST_F(ErrorHandlingMiddlewareTest, OnStatusReRegistration) {
    bool handler1_called = false;
    bool handler2_called = false;

    _error_mw->on_status(qb::http::status::FORBIDDEN,
                         [&handler1_called, this](auto ctx) {
                             handler1_called = true;
                             if (_session) _session->trace("Handler1_Forbidden");
                             ctx->response().body() = "Handled by Handler1 (Forbidden)";
                         });

    _error_mw->on_status(qb::http::status::FORBIDDEN, // Re-register for the same status
                         [&handler2_called, this](auto ctx) {
                             handler2_called = true;
                             if (_session) _session->trace("Handler2_Forbidden");
                             ctx->response().body() = "Handled by Handler2 (Forbidden)";
                         });

    auto trigger_task = std::make_shared<ErrorSignalerTask>("ErrorTrigger403", qb::http::status::FORBIDDEN);
    configure_router_and_make_request(trigger_task);

    EXPECT_FALSE(handler1_called); // First handler should not be called
    EXPECT_TRUE(handler2_called); // Second (last registered) handler should be called
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled by Handler2 (Forbidden)");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger403_triggered;Handler2_Forbidden");
}

TEST_F(ErrorHandlingMiddlewareTest, NullHandlersAreIgnored) {
    // Attempt to register null handlers
    _error_mw->on_status(qb::http::status::NOT_IMPLEMENTED, nullptr);
    _error_mw->on_status_range(qb::http::status::GATEWAY_TIMEOUT, qb::http::status::HTTP_VERSION_NOT_SUPPORTED,
                               nullptr);
    _error_mw->on_any_error(nullptr);

    // To verify they were ignored, set up a known (non-null) generic handler.
    // If the null handlers were somehow registered and caused issues, or if they
    // replaced the generic handler slot, this test would fail differently.
    bool generic_handler_called = false;
    _error_mw->on_any_error([&generic_handler_called, this](auto ctx, const auto &msg) {
        generic_handler_called = true;
        if (_session) _session->trace("NonNullGenericHandler");
        ctx->response().body() = "Handled by non-null generic: " + msg;
        ctx->response().status() = qb::http::status::VARIANT_ALSO_NEGOTIATES;
    });

    // Trigger an error that would have been caught by the null on_status if it was active
    auto trigger_task_specific = std::make_shared<ErrorSignalerTask>("ErrorTrigger501ForNullTest",
                                                                     qb::http::status::NOT_IMPLEMENTED,
                                                                     "Test specific null");
    configure_router_and_make_request(trigger_task_specific);

    EXPECT_TRUE(generic_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::VARIANT_ALSO_NEGOTIATES);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled by non-null generic: Test specific null");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger501ForNullTest_triggered;NonNullGenericHandler");

    // Reset and test for range
    _router = std::make_unique<qb::http::Router<MockErrorHandlingSession> >(); // Re-initialize router
    generic_handler_called = false;
    _session->reset();
    auto trigger_task_range = std::make_shared<ErrorSignalerTask>("ErrorTrigger504ForNullTest",
                                                                  qb::http::status::GATEWAY_TIMEOUT, "Test range null");
    configure_router_and_make_request(trigger_task_range);

    EXPECT_TRUE(generic_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::VARIANT_ALSO_NEGOTIATES);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled by non-null generic: Test range null");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger504ForNullTest_triggered;NonNullGenericHandler");
}

TEST_F(ErrorHandlingMiddlewareTest, OnStatusRangeWithInvalidCodes) {
    bool valid_code_handler_called = false;
    bool out_of_range_handler_called = false; // Should not be possible to be called via valid HTTP status

    // This handler should only be registered for HTTP_STATUS_OK (200)
    _error_mw->on_status_range(qb::http::status::OK, 700,
                               [&valid_code_handler_called, &out_of_range_handler_called, this](auto ctx) {
                                   if (ctx->response().status() == qb::http::status::OK) {
                                       valid_code_handler_called = true;
                                       if (_session) _session->trace("HandlerForValidCodeInRange");
                                       ctx->response().body() = "Handled 200 from mixed range";
                                   } else {
                                       out_of_range_handler_called = true; // Should not happen
                                       if (_session) _session->trace("HandlerForOutOfHttpRangeCode");
                                       ctx->response().body() = "Handled out-of-HTTP-range code";
                                   }
                               });

    // Sanity check with a generic handler to see what happens if we try to trigger an "invalid" code.
    // Realistically, the system won't set status codes outside 100-599 for errors.
    bool generic_handler_called_for_valid = false;
    _error_mw->on_any_error([&generic_handler_called_for_valid, this](auto ctx, const auto & /*msg*/) {
        generic_handler_called_for_valid = true;
        if (_session) _session->trace("GenericFallback");
        ctx->response().body() = "Generic fallback called";
        ctx->response().status() = qb::http::status::BAD_REQUEST;
    });

    // Test 1: Trigger HTTP_STATUS_OK (200), which is in the valid part of the range
    auto trigger_task_200 = std::make_shared<ErrorSignalerTask>("ErrorTrigger200", qb::http::status::OK);
    configure_router_and_make_request(trigger_task_200);

    EXPECT_TRUE(valid_code_handler_called);
    EXPECT_FALSE(out_of_range_handler_called);
    EXPECT_FALSE(generic_handler_called_for_valid);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled 200 from mixed range");
    EXPECT_EQ(_session->get_trace(), "ErrorTrigger200_triggered;HandlerForValidCodeInRange");

    // Test 2: Trigger an error that the range was supposed to cover (e.g. 500)
    _router = std::make_unique<qb::http::Router<MockErrorHandlingSession> >(); // Re-initialize router
    _session->reset();
    valid_code_handler_called = false; // reset flags
    out_of_range_handler_called = false;
    generic_handler_called_for_valid = false;

    // Clear existing handlers on _error_mw to make this test cleaner for the 500 case
    _error_mw = qb::http::error_handling_middleware<MockErrorHandlingSession>("TestErrorMW_ForInvalidRange");
    _error_mw->on_status_range(qb::http::status::OK, static_cast<qb::http::status>(700),
                               [&valid_code_handler_called, &out_of_range_handler_called, this](auto ctx) {
                                   // Same handler as above
                                   if (ctx->response().status() == qb::http::status::OK)
                                       valid_code_handler_called = true;
                                   else out_of_range_handler_called = true;
                               });
    // Add a generic handler AFTER the range one
    _error_mw->on_any_error([&generic_handler_called_for_valid, this](auto ctx, const auto & /*msg*/) {
        generic_handler_called_for_valid = true;
        ctx->response().body() = "Generic fallback called for 500";
    });


    auto trigger_task_500 = std::make_shared<ErrorSignalerTask>("ErrorTrigger500",
                                                                qb::http::status::INTERNAL_SERVER_ERROR);
    // We need to use the new _error_mw
    _router->use(trigger_task_500); // Add trigger
    _router->get("/error_trigger", normal_route_handler()); // Add route
    std::list<std::shared_ptr<qb::http::IAsyncTask<MockErrorHandlingSession> > > error_chain;
    error_chain.push_back(
        std::make_shared<qb::http::MiddlewareTask<MockErrorHandlingSession> >(_error_mw, _error_mw->name()));
    _router->set_error_task_chain(error_chain); // Set the new error MW
    _router->compile();
    _router->route(_session, create_request("/error_trigger"));

    EXPECT_FALSE(valid_code_handler_called); // Not a 200 error
    EXPECT_TRUE(out_of_range_handler_called);
    EXPECT_FALSE(generic_handler_called_for_valid); // Generic should not be called as range handler took precedence
}

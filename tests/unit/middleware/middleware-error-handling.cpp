/**
 * @file qbm/http/tests/unit/middleware/middleware-error-handling.cpp
 * @brief Unit tests for qb::http::ErrorHandlingMiddleware (status/range/generic dispatch).
 *
 * An erroring task (the shared ErrorSignalerTask, or a message-carrying variant)
 * runs first in the main chain and signals AsyncTaskResult::ERROR; the router then
 * routes the context into the configured error chain, where the
 * ErrorHandlingMiddleware dispatches to the most specific registered handler.
 * Execution order is recorded structurally into a shared vector (no stringly
 * marker surgery). A small helper centralises the
 * make_unique<Router> + set_error_task_chain boilerplate.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "../http.h"
#include "../middleware/error_handling.h"

#include "../../shared/middleware_test_fixture.h"
#include "../../shared/router_test_support.h"

namespace {

using Session = qb::http::test::MockMiddlewareSession;
using qb::http::test::ErrorSignalerTask;

/**
 * @brief Erroring task that also records into the order log and sets a context message.
 *
 * The shared ErrorSignalerTask covers the order-log + status path; this variant adds
 * the `__error_message` context slot (consumed by the generic handler) and a body,
 * for the cases that exercise message propagation.
 */
class MessageErrorSignalerTask : public qb::http::IMiddleware<Session> {
public:
    MessageErrorSignalerTask(std::string id, qb::http::status status, std::string message,
                             std::shared_ptr<std::vector<std::string>> order_log)
        : _id(std::move(id))
        , _status(status)
        , _message(std::move(message))
        , _order_log(std::move(order_log)) {}

    void
    process(std::shared_ptr<qb::http::Context<Session>> ctx) override {
        if (_order_log) {
            _order_log->push_back(_id);
        }
        ctx->response().status() = _status;
        if (!_message.empty()) {
            ctx->response().body() = "ErrorTrigger: " + _message;
            ctx->set("__error_message", _message);
        }
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
    }

    [[nodiscard]] std::string
    name() const override {
        return _id;
    }
    void
    cancel() override {}

private:
    std::string                               _id;
    qb::http::status                          _status;
    std::string                               _message;
    std::shared_ptr<std::vector<std::string>> _order_log;
};

class ErrorHandlingMiddlewareTest : public qb::http::test::MiddlewareTestFixture<Session> {
protected:
    std::shared_ptr<std::vector<std::string>>                       _order;
    std::shared_ptr<qb::http::ErrorHandlingMiddleware<Session>>     _error_mw;

    void
    SetUp() override {
        qb::http::test::MiddlewareTestFixture<Session>::SetUp();
        _order    = std::make_shared<std::vector<std::string>>();
        _error_mw = qb::http::error_handling_middleware<Session>("TestErrorMW");
    }

    /** @brief Wraps a middleware into the IAsyncTask error-chain element type. */
    static std::shared_ptr<qb::http::IAsyncTask<Session>>
    as_error_task(const std::shared_ptr<qb::http::IMiddleware<Session>> &mw) {
        return std::make_shared<qb::http::MiddlewareTask<Session>>(mw, mw->name());
    }

    /** @brief Records the order log into a normal route handler too (so we can assert it never runs). */
    qb::http::RouteHandlerFn<Session>
    traced_handler() {
        auto order = _order;
        return [this, order](std::shared_ptr<qb::http::Context<Session>> ctx) {
            if (order) {
                order->push_back("NormalHandler");
            }
            _session->_final_handler_called = true;
            ctx->response().status()        = qb::http::status::OK;
            ctx->response().body()          = "Normal handler reached successfully";
            ctx->complete();
        };
    }

    /**
     * @brief Builds a router with @p trigger first, @p error_chain as the error chain, and routes once.
     *
     * Centralises the make_unique<Router> + use(trigger) + get(handler) +
     * set_error_task_chain + compile + route boilerplate that every case repeated.
     */
    void
    run_with_error_chain(const std::shared_ptr<qb::http::IMiddleware<Session>>             &trigger,
                         const std::vector<std::shared_ptr<qb::http::IMiddleware<Session>>> &error_chain,
                         const std::string                                                  &path = "/error_trigger") {
        _router = std::make_unique<qb::http::Router<Session>>();
        _router->use(trigger);
        _router->get(path, traced_handler());

        std::vector<std::shared_ptr<qb::http::IAsyncTask<Session>>> chain;
        for (const auto &mw : error_chain) {
            chain.push_back(as_error_task(mw));
        }
        _router->set_error_task_chain(chain);

        _router->compile();
        _session->reset();
        _router->route(_session, create_request(qb::http::method::GET, path));
    }

    /** @brief Convenience: single-middleware error chain (= the fixture's _error_mw). */
    void
    run(const std::shared_ptr<qb::http::IMiddleware<Session>> &trigger) {
        run_with_error_chain(trigger, {_error_mw});
    }

    /**
     * @brief Routes a request whose terminal handler signals ERROR (no pre-handler trigger).
     *
     * Verifies that an error originating in the route handler — not a middleware —
     * also switches the context into the configured error chain.
     */
    void
    run_with_erroring_handler(qb::http::status handler_status, const std::string &path = "/error_trigger") {
        _router    = std::make_unique<qb::http::Router<Session>>();
        auto order = _order;
        _router->get(path, [order, handler_status](std::shared_ptr<qb::http::Context<Session>> ctx) {
            if (order) {
                order->push_back("HandlerErrors");
            }
            ctx->response().status() = handler_status;
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });

        std::vector<std::shared_ptr<qb::http::IAsyncTask<Session>>> chain{as_error_task(_error_mw)};
        _router->set_error_task_chain(chain);

        _router->compile();
        _session->reset();
        _router->route(_session, create_request(qb::http::method::GET, path));
    }

    [[nodiscard]] std::string
    body() const {
        return _session->_response.body().as<std::string>();
    }

    [[nodiscard]] const std::vector<std::string> &
    order() const {
        return *_order;
    }
};

// --- Specific / range / generic dispatch ------------------------------------

TEST_F(ErrorHandlingMiddlewareTest, SpecificStatusCodeHandler) {
    bool called = false;
    _error_mw->on_status(qb::http::status::BAD_GATEWAY, [&called, this](auto ctx) {
        called = true;
        _order->push_back("CustomBadGateway");
        ctx->response().status() = qb::http::status::BAD_GATEWAY;
        ctx->response().body()   = "Handled specifically by BadGateway handler.";
    });

    run(std::make_shared<ErrorSignalerTask<Session>>("ErrorTrigger502", qb::http::status::BAD_GATEWAY, nullptr, _order));

    EXPECT_TRUE(called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_EQ(body(), "Handled specifically by BadGateway handler.");
    EXPECT_EQ(order(), (std::vector<std::string>{"ErrorTrigger502", "CustomBadGateway"}));
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(ErrorHandlingMiddlewareTest, StatusCodeRangeHandler) {
    bool called = false;
    _error_mw->on_status_range(qb::http::status::BAD_REQUEST, qb::http::status::PAYMENT_REQUIRED, [&called, this](auto ctx) {
        called = true;
        _order->push_back("Custom4xxRange");
        ctx->response().body()   = "Handled by 4xx range: Original status " + std::to_string(static_cast<int>(ctx->response().status()));
        ctx->response().status() = qb::http::status::FORBIDDEN;
    });

    run(std::make_shared<ErrorSignalerTask<Session>>("ErrorTrigger401", qb::http::status::UNAUTHORIZED, nullptr, _order));

    EXPECT_TRUE(called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_EQ(body(), "Handled by 4xx range: Original status 401");
    EXPECT_EQ(order(), (std::vector<std::string>{"ErrorTrigger401", "Custom4xxRange"}));
}

TEST_F(ErrorHandlingMiddlewareTest, GenericErrorHandlerReceivesContextMessage) {
    bool        called = false;
    std::string received;
    _error_mw->on_any_error([&called, &received, this](auto ctx, const std::string &msg) {
        called   = true;
        received = msg;
        _order->push_back("Generic");
        ctx->response().status() = qb::http::status::NOT_IMPLEMENTED;
        ctx->response().body()   = "Generic handler caught: " + msg;
    });

    run(std::make_shared<MessageErrorSignalerTask>("ErrorTrigger500", qb::http::status::INTERNAL_SERVER_ERROR,
                                                   "Specific details for generic handler", _order));

    EXPECT_TRUE(called);
    EXPECT_EQ(received, "Specific details for generic handler");
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_IMPLEMENTED);
    EXPECT_EQ(body(), "Generic handler caught: Specific details for generic handler");
    EXPECT_EQ(order(), (std::vector<std::string>{"ErrorTrigger500", "Generic"}));
}

TEST_F(ErrorHandlingMiddlewareTest, GenericHandlerReceivesDefaultMessageWhenContextUnset) {
    bool        called = false;
    std::string received;
    _error_mw->on_any_error([&called, &received, this](auto ctx, const std::string &msg) {
        called   = true;
        received = msg;
        _order->push_back("GenericDefault");
        ctx->response().body()   = "Generic caught: " + msg;
        ctx->response().status() = qb::http::status::IM_A_TEAPOT;
    });

    // No __error_message set ⇒ middleware synthesises the default message.
    run(std::make_shared<ErrorSignalerTask<Session>>("ErrorTrigger403", qb::http::status::FORBIDDEN, nullptr, _order));

    const std::string expected = "Error encountered: status " + std::to_string(static_cast<int>(qb::http::status::FORBIDDEN));
    EXPECT_TRUE(called);
    EXPECT_EQ(received, expected);
    EXPECT_EQ(_session->_response.status(), qb::http::status::IM_A_TEAPOT);
    EXPECT_EQ(body(), "Generic caught: " + expected);
}

TEST_F(ErrorHandlingMiddlewareTest, NoMatchingHandlerLeavesErrorResponseUntouched) {
    run(std::make_shared<MessageErrorSignalerTask>("ErrorTrigger406", qb::http::status::NOT_ACCEPTABLE, "No handler for this", _order));

    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_ACCEPTABLE);
    EXPECT_EQ(body(), "ErrorTrigger: No handler for this");
    EXPECT_EQ(order(), (std::vector<std::string>{"ErrorTrigger406"}));
}

// --- Priority -----------------------------------------------------------------

TEST_F(ErrorHandlingMiddlewareTest, SpecificHandlerPriorityOverRange) {
    bool specific = false, range = false;
    _error_mw->on_status(qb::http::status::BAD_GATEWAY, [&specific, this](auto ctx) {
        specific = true;
        _order->push_back("Specific502");
        ctx->response().body() = "Handled by specific 502 handler.";
    });
    _error_mw->on_status_range(qb::http::status::INTERNAL_SERVER_ERROR, qb::http::status::SERVICE_UNAVAILABLE,
                               [&range, this](auto ctx) {
                                   range = true;
                                   _order->push_back("Range500-503");
                                   ctx->response().body() = "Handled by 500-503 range.";
                               });

    run(std::make_shared<ErrorSignalerTask<Session>>("ErrorTrigger502", qb::http::status::BAD_GATEWAY, nullptr, _order));

    EXPECT_TRUE(specific);
    EXPECT_FALSE(range);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_EQ(body(), "Handled by specific 502 handler.");
}

TEST_F(ErrorHandlingMiddlewareTest, RangeHandlerPriorityOverGeneric) {
    bool range = false, generic = false;
    _error_mw->on_status_range(qb::http::status::INTERNAL_SERVER_ERROR, qb::http::status::BAD_GATEWAY, [&range, this](auto ctx) {
        range = true;
        _order->push_back("Range500-502");
        ctx->response().body()   = "Handled by 500-502 range.";
        ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
    });
    _error_mw->on_any_error([&generic](auto, const auto &) { generic = true; });

    run(std::make_shared<ErrorSignalerTask<Session>>("ErrorTrigger501", qb::http::status::NOT_IMPLEMENTED, nullptr, _order));

    EXPECT_TRUE(range);
    EXPECT_FALSE(generic);
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(body(), "Handled by 500-502 range.");
}

TEST_F(ErrorHandlingMiddlewareTest, FirstMatchingRangeHandlerWins) {
    bool a = false, b = false;
    _error_mw->on_status_range(qb::http::status::INTERNAL_SERVER_ERROR, qb::http::status::NOT_IMPLEMENTED, [&a, this](auto ctx) {
        a = true;
        _order->push_back("HandlerA");
        ctx->response().body() = "Handled by A (500-501).";
    });
    _error_mw->on_status_range(qb::http::status::NOT_IMPLEMENTED, qb::http::status::BAD_GATEWAY, [&b, this](auto ctx) {
        b = true;
        _order->push_back("HandlerB");
        ctx->response().body() = "Handled by B (501-502).";
    });

    run(std::make_shared<ErrorSignalerTask<Session>>("ErrorTrigger501", qb::http::status::NOT_IMPLEMENTED, nullptr, _order));

    EXPECT_TRUE(a);
    EXPECT_FALSE(b);
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_IMPLEMENTED);
    EXPECT_EQ(body(), "Handled by A (500-501).");
}

// --- Throwing / robustness ---------------------------------------------------

TEST_F(ErrorHandlingMiddlewareTest, GenericHandlerRunsWhenSpecificHandlerThrows) {
    bool generic = false;
    _error_mw->on_status(qb::http::status::FORBIDDEN, [this](auto /*ctx*/) {
        _order->push_back("SpecificThrows");
        throw std::runtime_error("specific handler failure");
    });
    _error_mw->on_any_error([&generic, this](auto ctx, const auto &msg) {
        generic = true;
        _order->push_back("GenericAfterThrow");
        ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
        ctx->response().body()   = "Generic fallback: " + std::string(msg);
    });

    run(std::make_shared<MessageErrorSignalerTask>("ErrorTrigger403", qb::http::status::FORBIDDEN, "forbidden path", _order));

    EXPECT_TRUE(generic);
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(body(), "Generic fallback: forbidden path");
    EXPECT_EQ(order(), (std::vector<std::string>{"ErrorTrigger403", "SpecificThrows", "GenericAfterThrow"}));
}

TEST_F(ErrorHandlingMiddlewareTest, GenericHandlerThrowsLeavesPriorResponseIntact) {
    // When the generic handler itself throws, the middleware swallows it and still
    // completes; the response reflects whatever the (partial) handler set before throwing.
    _error_mw->on_any_error([this](auto ctx, const auto &) {
        _order->push_back("GenericThrows");
        ctx->response().status() = qb::http::status::SERVICE_UNAVAILABLE;
        ctx->response().body()   = "partial-before-throw";
        throw std::runtime_error("generic handler failure");
    });

    EXPECT_NO_THROW(
        run(std::make_shared<ErrorSignalerTask<Session>>("ErrorTrigger500", qb::http::status::INTERNAL_SERVER_ERROR, nullptr, _order)));

    // The throw aborted the handler mid-way; the mutations it made before throwing persist.
    EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(body(), "partial-before-throw");
    EXPECT_EQ(order(), (std::vector<std::string>{"ErrorTrigger500", "GenericThrows"}));
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(ErrorHandlingMiddlewareTest, ErrorHandlerCanModifyResponse) {
    bool called = false;
    _error_mw->on_status(qb::http::status::NOT_FOUND, [&called, this](auto ctx) {
        called = true;
        _order->push_back("Modify404");
        ctx->response().status() = qb::http::status::EXPECTATION_FAILED;
        ctx->response().body()   = "This was a 404, now it is a 417 with custom message.";
        ctx->response().set_header("X-Error-Handled", "True");
    });

    run(std::make_shared<MessageErrorSignalerTask>("ErrorTrigger404", qb::http::status::NOT_FOUND, "Original 404 body", _order));

    EXPECT_TRUE(called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::EXPECTATION_FAILED);
    EXPECT_EQ(body(), "This was a 404, now it is a 417 with custom message.");
    EXPECT_EQ(std::string(_session->_response.header("X-Error-Handled")), "True");
}

TEST_F(ErrorHandlingMiddlewareTest, OnStatusReRegistrationKeepsLast) {
    bool first = false, second = false;
    _error_mw->on_status(qb::http::status::FORBIDDEN, [&first, this](auto ctx) {
        first = true;
        _order->push_back("First");
        ctx->response().body() = "Handled by Handler1 (Forbidden)";
    });
    _error_mw->on_status(qb::http::status::FORBIDDEN, [&second, this](auto ctx) {
        second = true;
        _order->push_back("Second");
        ctx->response().body() = "Handled by Handler2 (Forbidden)";
    });

    run(std::make_shared<ErrorSignalerTask<Session>>("ErrorTrigger403", qb::http::status::FORBIDDEN, nullptr, _order));

    EXPECT_FALSE(first);
    EXPECT_TRUE(second);
    EXPECT_EQ(body(), "Handled by Handler2 (Forbidden)");
    EXPECT_EQ(order(), (std::vector<std::string>{"ErrorTrigger403", "Second"}));
}

TEST_F(ErrorHandlingMiddlewareTest, NullHandlersAreIgnored) {
    _error_mw->on_status(qb::http::status::NOT_IMPLEMENTED, nullptr);
    _error_mw->on_status_range(qb::http::status::GATEWAY_TIMEOUT, qb::http::status::HTTP_VERSION_NOT_SUPPORTED, nullptr);
    _error_mw->on_any_error(nullptr);

    bool generic = false;
    _error_mw->on_any_error([&generic, this](auto ctx, const auto &msg) {
        generic = true;
        _order->push_back("NonNullGeneric");
        ctx->response().body()   = "Handled by non-null generic: " + std::string(msg);
        ctx->response().status() = qb::http::status::VARIANT_ALSO_NEGOTIATES;
    });

    run(std::make_shared<MessageErrorSignalerTask>("ErrorTrigger501", qb::http::status::NOT_IMPLEMENTED, "Test specific null", _order));

    EXPECT_TRUE(generic);
    EXPECT_EQ(_session->_response.status(), qb::http::status::VARIANT_ALSO_NEGOTIATES);
    EXPECT_EQ(body(), "Handled by non-null generic: Test specific null");
}

// --- Chains ------------------------------------------------------------------

TEST_F(ErrorHandlingMiddlewareTest, FirstChainEntryDeclinesSecondHandles) {
    // First error MW has no matching handler and no generic ⇒ it completes COMPLETE,
    // but the chain's first matching middleware is the one that owns the status.
    // Here mw1 handles 500 (and changes status to 200), so mw2 must NOT run.
    auto mw1 = qb::http::error_handling_middleware<Session>("ErrorMW1");
    auto mw2 = qb::http::error_handling_middleware<Session>("ErrorMW2");
    bool h1 = false, h2 = false;

    mw1->on_status(qb::http::status::INTERNAL_SERVER_ERROR, [&h1, this](auto ctx) {
        h1 = true;
        _order->push_back("MW1");
        ctx->response().body()   = "Handled by MW1";
        ctx->response().status() = qb::http::status::OK;
    });
    mw2->on_status(qb::http::status::INTERNAL_SERVER_ERROR, [&h2, this](auto ctx) {
        h2 = true;
        _order->push_back("MW2");
        ctx->response().body() = "Handled by MW2";
    });

    run_with_error_chain(std::make_shared<ErrorSignalerTask<Session>>("ErrorTrigger500", qb::http::status::INTERNAL_SERVER_ERROR, nullptr, _order),
                         {mw1, mw2});

    EXPECT_TRUE(h1);
    EXPECT_FALSE(h2);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(body(), "Handled by MW1");
    EXPECT_EQ(order(), (std::vector<std::string>{"ErrorTrigger500", "MW1"}));
}

TEST_F(ErrorHandlingMiddlewareTest, ErrorSignaledFromRouteHandlerEntersErrorChain) {
    // The error originates in the terminal handler (NORMAL_CHAIN), not a middleware.
    bool called = false;
    _error_mw->on_status(qb::http::status::CONFLICT, [&called, this](auto ctx) {
        called = true;
        _order->push_back("Handle409");
        ctx->response().body() = "handler-error handled by error MW";
    });

    run_with_erroring_handler(qb::http::status::CONFLICT);

    EXPECT_TRUE(called);
    EXPECT_FALSE(_session->_final_handler_called); // handler ran but signaled ERROR, not completion.
    EXPECT_EQ(_session->_response.status(), qb::http::status::CONFLICT);
    EXPECT_EQ(body(), "handler-error handled by error MW");
    EXPECT_EQ(order(), (std::vector<std::string>{"HandlerErrors", "Handle409"}));
}

TEST_F(ErrorHandlingMiddlewareTest, FactoryFunctionCreatesUsableInstance) {
    auto factory_mw = qb::http::error_handling_middleware<Session>("FactoryTestErrorMW");
    ASSERT_NE(factory_mw, nullptr);
    EXPECT_EQ(factory_mw->name(), "FactoryTestErrorMW");

    bool called = false;
    factory_mw->on_status(qb::http::status::NOT_FOUND, [&called, this](auto ctx) {
        called = true;
        _order->push_back("Factory404");
        ctx->response().body()   = "Handled by factory MW (404)";
        ctx->response().status() = qb::http::status::OK;
    });

    run_with_error_chain(std::make_shared<ErrorSignalerTask<Session>>("ErrorTrigger404", qb::http::status::NOT_FOUND, nullptr, _order),
                         {factory_mw});

    EXPECT_TRUE(called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(body(), "Handled by factory MW (404)");
}

// --- on_status_range invalid-code handling (split from the legacy mixed test) -

TEST_F(ErrorHandlingMiddlewareTest, OnStatusRangeRegistersOnlyValidHttpCodes) {
    // Range OK(200)..700 must only register handlers for codes in [100,600).
    // 200 (in valid window) is dispatched; 700 is never a real status, so the
    // generic handler must catch a genuinely-out-of-window error instead.
    bool in_window = false;
    _error_mw->on_status_range(qb::http::status::OK, static_cast<qb::http::status>(700), [&in_window, this](auto ctx) {
        in_window = true;
        _order->push_back("RangeOK-700");
        ctx->response().body() = "Handled 200 from mixed range";
    });

    run(std::make_shared<ErrorSignalerTask<Session>>("ErrorTrigger200", qb::http::status::OK, nullptr, _order));

    EXPECT_TRUE(in_window);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(body(), "Handled 200 from mixed range");
    EXPECT_EQ(order(), (std::vector<std::string>{"ErrorTrigger200", "RangeOK-700"}));
}

TEST_F(ErrorHandlingMiddlewareTest, OnStatusRangeStillCoversInWindowCodesNotInGenericFallback) {
    // A 500 lies inside [OK,700) ∩ [100,600), so the range handler — registered
    // before the generic — owns it; the generic must NOT fire.
    bool range = false, generic = false;
    _error_mw->on_status_range(qb::http::status::OK, static_cast<qb::http::status>(700), [&range, this](auto ctx) {
        range = true;
        _order->push_back("Range");
        ctx->response().body() = "range handled 500";
    });
    _error_mw->on_any_error([&generic, this](auto ctx, const auto &) {
        generic = true;
        _order->push_back("Generic");
        ctx->response().body() = "generic 500";
    });

    run(std::make_shared<ErrorSignalerTask<Session>>("ErrorTrigger500", qb::http::status::INTERNAL_SERVER_ERROR, nullptr, _order));

    EXPECT_TRUE(range);
    EXPECT_FALSE(generic);
    EXPECT_EQ(body(), "range handled 500");
    EXPECT_EQ(order(), (std::vector<std::string>{"ErrorTrigger500", "Range"}));
}

} // namespace

#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/recaptcha.h" // The adapted RecaptchaMiddleware
#include "../routing/middleware.h"   // For MiddlewareTask and IMiddleware

#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

// --- Mock Session for RecaptchaMiddleware Tests ---
struct MockRecaptchaSession {
    qb::http::Response                       _response;
    std::string                              _session_id_str = "recaptcha_test_session";
    std::optional<qb::http::RecaptchaResult> _recaptcha_result_in_context;
    bool                                     _final_handler_called = false;
    std::string                              _trace;

    qb::http::Response &
    get_response_ref() {
        return _response;
    }

    MockRecaptchaSession &
    operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    void
    reset() {
        _response = qb::http::Response();
        _recaptcha_result_in_context.reset();
        _final_handler_called = false;
        _trace.clear();
    }

    void
    trace(const std::string &point) {
        if (!_trace.empty())
            _trace += ";";
        _trace += point;
    }
};

// --- Test Fixture for RecaptchaMiddleware ---
class RecaptchaMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockRecaptchaSession>                   _session;
    std::unique_ptr<qb::http::Router<MockRecaptchaSession>> _router;

    void
    SetUp() override {
        _session = std::make_shared<MockRecaptchaSession>();
        _router  = std::make_unique<qb::http::Router<MockRecaptchaSession>>();
    }

    qb::http::Request
    create_request(const std::string                        &token_value = "",
                   qb::http::RecaptchaOptions::TokenLocation location    = qb::http::RecaptchaOptions::TokenLocation::Body,
                   const std::string &field_name = "g-recaptcha-response", bool body_as_form = false) {
        qb::http::Request req;
        req.method() = qb::http::method::POST; // Often used with forms needing reCAPTCHA
        req.uri()    = qb::io::uri("/submit_form");

        if (!token_value.empty()) {
            switch (location) {
                case qb::http::RecaptchaOptions::TokenLocation::Header:
                    req.set_header(field_name, token_value);
                    break;
                case qb::http::RecaptchaOptions::TokenLocation::Body:
                    if (body_as_form) {
                        qb::http::Form form;
                        form.add(field_name, token_value);
                        req.body() = std::move(form);
                        req.set_header("Content-Type", "application/x-www-form-urlencoded");
                    } else {
                        qb::json body_json;
                        body_json[field_name] = token_value;
                        req.body()            = body_json.dump();
                        req.set_header("Content-Type", "application/json");
                    }
                    break;
                case qb::http::RecaptchaOptions::TokenLocation::Query:
                    req.uri() = qb::io::uri("/submit_form?" + field_name + "=" + token_value);
                    break;
            }
        }
        return req;
    }

    qb::http::RouteHandlerFn<MockRecaptchaSession>
    success_handler() {
        return [this](std::shared_ptr<qb::http::Context<MockRecaptchaSession>> ctx) {
            if (_session) {
                _session->_final_handler_called = true;
                if (ctx->has("recaptcha_result")) {
                    _session->_recaptcha_result_in_context = ctx->template get<qb::http::RecaptchaResult>("recaptcha_result");
                }
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Form Submitted Successfully";
            ctx->complete();
        };
    }

    void
    configure_router_and_run(std::shared_ptr<qb::http::RecaptchaMiddleware<MockRecaptchaSession>> recap_mw, qb::http::Request request) {
        _router->use(recap_mw);
        _router->post("/submit_form", success_handler()); // Assuming POST for reCAPTCHA-protected forms
        _router->compile();

        _session->reset();

        // Tests inject a deterministic verification client, so the async callback
        // completes synchronously without contacting Google.
        _router->route(_session, std::move(request));
    }
};

TEST_F(RecaptchaMiddlewareTest, MissingToken) {
    qb::http::RecaptchaOptions opts("test_secret");
    auto                       recap_mw = qb::http::recaptcha_middleware<MockRecaptchaSession>(opts);
    configure_router_and_run(recap_mw, create_request("")); // Empty token

    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_NE(_session->_response.body().as<std::string>().find("reCAPTCHA token"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST(RecaptchaRequestEncoding, VerificationBodyEscapesFormReservedCharacters) {
    const std::string body =
        qb::http::detail::build_recaptcha_verification_body("secret&with=reserved+chars%", "token+with&separators=and%percent");

    EXPECT_EQ(body, "secret=secret%26with%3Dreserved%2Bchars%25&response=token%2Bwith%26separators%3Dand%25percent");
}

TEST_F(RecaptchaMiddlewareTest, ValidTokenPassesWithInjectedVerifier) {
    qb::http::RecaptchaOptions opts("fake_secret_for_mocked_success");
    opts.min_score(0.5f);
    auto recap_mw        = qb::http::recaptcha_middleware<MockRecaptchaSession>(opts);
    bool verifier_called = false;
    recap_mw->verification_client([&](qb::http::Request request, qb::http::RecaptchaMiddleware<MockRecaptchaSession>::VerificationCallback cb) {
        verifier_called = true;
        EXPECT_EQ(request.method(), qb::http::method::POST);
        EXPECT_NE(request.body().as<std::string>().find("response=valid_mocked_token"), std::string::npos);

        qb::http::Response response;
        response.status() = qb::http::status::OK;
        response.body()   = R"({"success":true,"score":0.9,"action":"submit","hostname":"test.com"})";
        cb(qb::http::async::Reply{std::move(request), std::move(response)});
    });

    configure_router_and_run(recap_mw, create_request("valid_mocked_token"));

    EXPECT_TRUE(verifier_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_recaptcha_result_in_context.has_value());
    EXPECT_TRUE(_session->_recaptcha_result_in_context->success);
    EXPECT_GE(_session->_recaptcha_result_in_context->score, 0.5f);
}

TEST_F(RecaptchaMiddlewareTest, ScorelessV2SuccessPassesDefaultScoreThreshold) {
    qb::http::RecaptchaOptions opts("fake_secret_for_mocked_v2_success");
    auto                       recap_mw = qb::http::recaptcha_middleware<MockRecaptchaSession>(opts);
    recap_mw->verification_client([](qb::http::Request request, qb::http::RecaptchaMiddleware<MockRecaptchaSession>::VerificationCallback cb) {
        qb::http::Response response;
        response.status() = qb::http::status::OK;
        response.body()   = R"({"success":true,"hostname":"test.com"})";
        cb(qb::http::async::Reply{std::move(request), std::move(response)});
    });

    configure_router_and_run(recap_mw, create_request("valid_mocked_v2_token"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_recaptcha_result_in_context.has_value());
    EXPECT_TRUE(_session->_recaptcha_result_in_context->success);
    EXPECT_FALSE(_session->_recaptcha_result_in_context->has_score);
}

TEST_F(RecaptchaMiddlewareTest, ExplicitV3RejectsScorelessSuccess) {
    auto recap_mw = qb::http::recaptcha_middleware<MockRecaptchaSession>(qb::http::RecaptchaOptions::v3("fake_secret_for_mocked_scoreless_v3"));
    recap_mw->verification_client([](qb::http::Request request, qb::http::RecaptchaMiddleware<MockRecaptchaSession>::VerificationCallback cb) {
        qb::http::Response response;
        response.status() = qb::http::status::OK;
        response.body()   = R"({"success":true,"hostname":"test.com"})";
        cb(qb::http::async::Reply{std::move(request), std::move(response)});
    });

    configure_router_and_run(recap_mw, create_request("scoreless_mocked_v3_token"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_NE(_session->_response.body().as<std::string>().find("Score is required"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(RecaptchaMiddlewareTest, TokenExtractionFromUrlEncodedFormBody) {
    qb::http::RecaptchaOptions opts("test_secret");
    auto                       recap_mw = qb::http::recaptcha_middleware<MockRecaptchaSession>(opts);
    recap_mw->verification_client([](qb::http::Request request, qb::http::RecaptchaMiddleware<MockRecaptchaSession>::VerificationCallback cb) {
        EXPECT_NE(request.body().as<std::string>().find("response=form%2Btoken%26reserved"), std::string::npos);

        qb::http::Response response;
        response.status() = qb::http::status::OK;
        response.body()   = R"({"success":true,"score":0.9})";
        cb(qb::http::async::Reply{std::move(request), std::move(response)});
    });

    configure_router_and_run(
        recap_mw, create_request("form+token&reserved", qb::http::RecaptchaOptions::TokenLocation::Body, "g-recaptcha-response", true));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(RecaptchaMiddlewareTest, TokenScoreTooLowRejectsWithInjectedVerifier) {
    qb::http::RecaptchaOptions opts("fake_secret_for_mocked_low_score");
    opts.min_score(0.7f);
    auto recap_mw = qb::http::recaptcha_middleware<MockRecaptchaSession>(opts);
    recap_mw->verification_client([](qb::http::Request request, qb::http::RecaptchaMiddleware<MockRecaptchaSession>::VerificationCallback cb) {
        qb::http::Response response;
        response.status() = qb::http::status::OK;
        response.body()   = R"({"success":true,"score":0.3})";
        cb(qb::http::async::Reply{std::move(request), std::move(response)});
    });

    configure_router_and_run(recap_mw, create_request("mocked_token_low_score"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_NE(_session->_response.body().as<std::string>().find("below threshold"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(RecaptchaMiddlewareTest, GoogleApiErrorRejectsWithInjectedVerifier) {
    qb::http::RecaptchaOptions opts("invalid_secret_for_google_error");
    auto                       recap_mw = qb::http::recaptcha_middleware<MockRecaptchaSession>(opts);
    recap_mw->verification_client([](qb::http::Request request, qb::http::RecaptchaMiddleware<MockRecaptchaSession>::VerificationCallback cb) {
        qb::http::Response response;
        response.status() = qb::http::status::OK;
        response.body()   = R"({"success":false,"error-codes":["invalid-input-secret"]})";
        cb(qb::http::async::Reply{std::move(request), std::move(response)});
    });

    configure_router_and_run(recap_mw, create_request("mocked_token_google_error"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_NE(_session->_response.body().as<std::string>().find("invalid-input-secret"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(RecaptchaMiddlewareTest, TokenExtractionFromHeader) {
    qb::http::RecaptchaOptions opts("test_secret");
    opts.from_header("X-reCAPTCHA-Token");
    auto recap_mw = qb::http::recaptcha_middleware<MockRecaptchaSession>(opts);
    recap_mw->verification_client([](qb::http::Request request, qb::http::RecaptchaMiddleware<MockRecaptchaSession>::VerificationCallback cb) {
        EXPECT_NE(request.body().as<std::string>().find("response=header_token"), std::string::npos);

        qb::http::Response response;
        response.status() = qb::http::status::OK;
        response.body()   = R"({"success":true,"score":1.0})";
        cb(qb::http::async::Reply{std::move(request), std::move(response)});
    });

    configure_router_and_run(recap_mw, create_request("header_token", qb::http::RecaptchaOptions::TokenLocation::Header, "X-reCAPTCHA-Token"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
}

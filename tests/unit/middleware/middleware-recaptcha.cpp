/**
 * @file qbm/http/tests/unit/middleware/middleware-recaptcha.cpp
 * @brief Unit tests for qb::http::RecaptchaMiddleware (token extraction + verification).
 *
 * The production middleware calls Google's siteverify endpoint over HTTPS; here a
 * deterministic verification_client is injected so the async callback fires
 * synchronously and offline. Every injected-verifier test asserts whether the
 * verifier was reached (proving the extract→verify path or the short-circuit on a
 * missing token), pins full rejection-reason text, and covers v2/v3/Auto challenge
 * modes plus the verifier-failure paths (malformed JSON, non-200 transport).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <gtest/gtest.h>

#include <qbm/http/http.h>
#include <qbm/http/middleware/recaptcha.h>

#include "../../shared/middleware_test_fixture.h"

namespace {

/**
 * @brief Recaptcha session: extends the shared mock with the context-recovered result.
 */
struct MockRecaptchaSession : qb::http::test::MockMiddlewareSession {
    std::optional<qb::http::RecaptchaResult> _recaptcha_result_in_context;

    void
    reset() {
        qb::http::test::MockMiddlewareSession::reset();
        _recaptcha_result_in_context.reset();
    }
};

using VClient   = qb::http::RecaptchaMiddleware<MockRecaptchaSession>::VerificationClient;
using VCallback = qb::http::RecaptchaMiddleware<MockRecaptchaSession>::VerificationCallback;

class RecaptchaMiddlewareTest : public qb::http::test::MiddlewareTestFixture<MockRecaptchaSession> {
protected:
    /**
     * @brief Builds a POST /submit_form request carrying the token in the configured location.
     */
    qb::http::Request
    recaptcha_request(const std::string                        &token_value = "",
                      qb::http::RecaptchaOptions::TokenLocation location    = qb::http::RecaptchaOptions::TokenLocation::Body,
                      const std::string &field_name = "g-recaptcha-response", bool body_as_form = false) {
        qb::http::Request req;
        req.method() = qb::http::method::POST;
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

    /** @brief Terminal handler that recovers the RecaptchaResult from context. */
    qb::http::RouteHandlerFn<MockRecaptchaSession>
    recaptcha_handler() {
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
    run_recaptcha(std::shared_ptr<qb::http::RecaptchaMiddleware<MockRecaptchaSession>> recap_mw, qb::http::Request request) {
        _router = std::make_unique<qb::http::Router<MockRecaptchaSession>>();
        // Recover the context-stored RecaptchaResult on EVERY finalisation, success
        // OR failure. The terminal handler only runs on the CONTINUE (success) path,
        // so on a rejection (403) it never executes — yet the middleware stores the
        // result into the context *before* deciding to reject (recaptcha.h: the
        // `set<RecaptchaResult>("recaptcha_result", ...)` call precedes the failure
        // branch). A POST_HANDLER_EXECUTION lifecycle hook fires during finalisation
        // regardless of outcome, so it is the correct, outcome-independent place to
        // observe what the framework actually persisted on the failure paths.
        _router->use(
            [this](std::shared_ptr<qb::http::Context<MockRecaptchaSession>> ctx, std::function<void()> next) {
                ctx->add_lifecycle_hook([this](qb::http::Context<MockRecaptchaSession> &c, qb::http::HookPoint point) {
                    if (point == qb::http::HookPoint::POST_HANDLER_EXECUTION && _session && c.has("recaptcha_result")) {
                        _session->_recaptcha_result_in_context = c.template get<qb::http::RecaptchaResult>("recaptcha_result");
                    }
                });
                next();
            },
            "RecaptchaResultRecoveryHook");
        _router->use(std::move(recap_mw));
        _router->post("/submit_form", recaptcha_handler());
        _router->compile();

        _session->reset();
        _router->route(_session, std::move(request));
    }

    /** @brief Builds a verifier that fabricates a 200 OK Google response body. */
    static VClient
    ok_verifier(std::string json_body, bool *called = nullptr) {
        return [json_body = std::move(json_body), called](qb::http::Request request, VCallback cb) mutable {
            if (called) {
                *called = true;
            }
            qb::http::Response response;
            response.status() = qb::http::status::OK;
            response.body()   = json_body;
            cb(qb::http::async::Reply{std::move(request), std::move(response)});
        };
    }

    [[nodiscard]] std::string
    body() const {
        return _session->_response.body().as<std::string>();
    }
};

// --- Token extraction / short-circuit ---------------------------------------

TEST_F(RecaptchaMiddlewareTest, MissingTokenShortCircuitsBeforeVerifier) {
    bool verifier_called = false;
    auto recap_mw        = qb::http::recaptcha_middleware<MockRecaptchaSession>(qb::http::RecaptchaOptions("test_secret"));
    recap_mw->verification_client(ok_verifier(R"({"success":true})", &verifier_called));

    run_recaptcha(recap_mw, recaptcha_request("")); // no token

    EXPECT_FALSE(verifier_called) << "Verifier must NOT be contacted when the token is missing.";
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_NE(body().find("reCAPTCHA token"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST(RecaptchaRequestEncoding, VerificationBodyEscapesFormReservedCharacters) {
    const std::string b =
        qb::http::detail::build_recaptcha_verification_body("secret&with=reserved+chars%", "token+with&separators=and%percent");
    EXPECT_EQ(b, "secret=secret%26with%3Dreserved%2Bchars%25&response=token%2Bwith%26separators%3Dand%25percent");
}

TEST_F(RecaptchaMiddlewareTest, ValidTokenPassesWithInjectedVerifier) {
    qb::http::RecaptchaOptions opts("fake_secret_for_mocked_success");
    opts.min_score(0.5f);
    auto recap_mw        = qb::http::recaptcha_middleware<MockRecaptchaSession>(opts);
    bool verifier_called = false;
    recap_mw->verification_client([&](qb::http::Request request, VCallback cb) {
        verifier_called = true;
        EXPECT_EQ(request.method(), qb::http::method::POST);
        EXPECT_NE(request.body().as<std::string>().find("response=valid_mocked_token"), std::string::npos);

        qb::http::Response response;
        response.status() = qb::http::status::OK;
        response.body()   = R"({"success":true,"score":0.9,"action":"submit","hostname":"test.com"})";
        cb(qb::http::async::Reply{std::move(request), std::move(response)});
    });

    run_recaptcha(recap_mw, recaptcha_request("valid_mocked_token"));

    EXPECT_TRUE(verifier_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_recaptcha_result_in_context.has_value());
    EXPECT_TRUE(_session->_recaptcha_result_in_context->success);
    EXPECT_GE(_session->_recaptcha_result_in_context->score, 0.5f);
    EXPECT_EQ(_session->_recaptcha_result_in_context->action, "submit");
    EXPECT_EQ(_session->_recaptcha_result_in_context->hostname, "test.com");
}

TEST_F(RecaptchaMiddlewareTest, TokenExtractionFromUrlEncodedFormBody) {
    bool verifier_called = false;
    auto recap_mw        = qb::http::recaptcha_middleware<MockRecaptchaSession>(qb::http::RecaptchaOptions("test_secret"));
    recap_mw->verification_client([&](qb::http::Request request, VCallback cb) {
        verifier_called = true;
        EXPECT_NE(request.body().as<std::string>().find("response=form%2Btoken%26reserved"), std::string::npos);
        qb::http::Response response;
        response.status() = qb::http::status::OK;
        response.body()   = R"({"success":true,"score":0.9})";
        cb(qb::http::async::Reply{std::move(request), std::move(response)});
    });

    run_recaptcha(recap_mw,
                  recaptcha_request("form+token&reserved", qb::http::RecaptchaOptions::TokenLocation::Body, "g-recaptcha-response", true));

    EXPECT_TRUE(verifier_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(RecaptchaMiddlewareTest, TokenExtractionFromHeader) {
    qb::http::RecaptchaOptions opts("test_secret");
    opts.from_header("X-reCAPTCHA-Token");
    auto recap_mw        = qb::http::recaptcha_middleware<MockRecaptchaSession>(opts);
    bool verifier_called = false;
    recap_mw->verification_client([&](qb::http::Request request, VCallback cb) {
        verifier_called = true;
        EXPECT_NE(request.body().as<std::string>().find("response=header_token"), std::string::npos);
        qb::http::Response response;
        response.status() = qb::http::status::OK;
        response.body()   = R"({"success":true,"score":1.0})";
        cb(qb::http::async::Reply{std::move(request), std::move(response)});
    });

    run_recaptcha(recap_mw, recaptcha_request("header_token", qb::http::RecaptchaOptions::TokenLocation::Header, "X-reCAPTCHA-Token"));

    EXPECT_TRUE(verifier_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
}

// --- Challenge-type semantics (v2 / v3 / Auto) ------------------------------

TEST_F(RecaptchaMiddlewareTest, AutoModeAcceptsScorelessSuccess) {
    // Default (Auto) accepts a v2-shaped scoreless success.
    bool verifier_called = false;
    auto recap_mw        = qb::http::recaptcha_middleware<MockRecaptchaSession>(qb::http::RecaptchaOptions("fake_secret_auto"));
    recap_mw->verification_client(ok_verifier(R"({"success":true,"hostname":"test.com"})", &verifier_called));

    run_recaptcha(recap_mw, recaptcha_request("auto_scoreless_token"));

    EXPECT_TRUE(verifier_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_recaptcha_result_in_context.has_value());
    EXPECT_TRUE(_session->_recaptcha_result_in_context->success);
    EXPECT_FALSE(_session->_recaptcha_result_in_context->has_score);
}

TEST_F(RecaptchaMiddlewareTest, AutoModeEnforcesScoreThresholdWhenScorePresent) {
    // Auto mode: when Google DOES return a score, the threshold is enforced.
    bool                       verifier_called = false;
    qb::http::RecaptchaOptions opts("fake_secret_auto_score");
    opts.min_score(0.7f); // default challenge_type is Auto
    auto recap_mw = qb::http::recaptcha_middleware<MockRecaptchaSession>(opts);
    recap_mw->verification_client(ok_verifier(R"({"success":true,"score":0.4})", &verifier_called));

    run_recaptcha(recap_mw, recaptcha_request("auto_low_score_token"));

    EXPECT_TRUE(verifier_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_NE(body().find("below threshold"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(RecaptchaMiddlewareTest, V2ModeIgnoresScoreThreshold) {
    // Explicit V2 ignores the score even when present and below the configured min.
    bool                       verifier_called = false;
    qb::http::RecaptchaOptions opts            = qb::http::RecaptchaOptions::v2("fake_secret_v2");
    opts.min_score(0.9f);
    auto recap_mw = qb::http::recaptcha_middleware<MockRecaptchaSession>(opts);
    recap_mw->verification_client(ok_verifier(R"({"success":true,"score":0.1})", &verifier_called));

    run_recaptcha(recap_mw, recaptcha_request("v2_low_score_token"));

    EXPECT_TRUE(verifier_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(RecaptchaMiddlewareTest, ExplicitV3RejectsScorelessSuccess) {
    bool verifier_called = false;
    auto recap_mw = qb::http::recaptcha_middleware<MockRecaptchaSession>(qb::http::RecaptchaOptions::v3("fake_secret_for_mocked_scoreless_v3"));
    recap_mw->verification_client(ok_verifier(R"({"success":true,"hostname":"test.com"})", &verifier_called));

    run_recaptcha(recap_mw, recaptcha_request("scoreless_mocked_v3_token"));

    EXPECT_TRUE(verifier_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_NE(body().find("Score is required for reCAPTCHA v3."), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(RecaptchaMiddlewareTest, V3AcceptsScoreExactlyAtThreshold) {
    // Boundary: score == min_score must PASS (>= semantics, not >).
    bool verifier_called = false;
    auto recap_mw        = qb::http::recaptcha_middleware<MockRecaptchaSession>(qb::http::RecaptchaOptions::v3("fake_secret_boundary", 0.5f));
    recap_mw->verification_client(ok_verifier(R"({"success":true,"score":0.5})", &verifier_called));

    run_recaptcha(recap_mw, recaptcha_request("boundary_token"));

    EXPECT_TRUE(verifier_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(RecaptchaMiddlewareTest, TokenScoreTooLowRejectsWithInjectedVerifier) {
    bool                       verifier_called = false;
    qb::http::RecaptchaOptions opts("fake_secret_for_mocked_low_score");
    opts.min_score(0.7f).challenge_type(qb::http::RecaptchaOptions::ChallengeType::V3);
    auto recap_mw = qb::http::recaptcha_middleware<MockRecaptchaSession>(opts);
    recap_mw->verification_client(ok_verifier(R"({"success":true,"score":0.3})", &verifier_called));

    run_recaptcha(recap_mw, recaptcha_request("mocked_token_low_score"));

    EXPECT_TRUE(verifier_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_NE(body().find("is below threshold"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

// --- Verifier-side failure paths --------------------------------------------

TEST_F(RecaptchaMiddlewareTest, GoogleApiErrorSurfacesErrorCodes) {
    bool verifier_called = false;
    auto recap_mw        = qb::http::recaptcha_middleware<MockRecaptchaSession>(qb::http::RecaptchaOptions("invalid_secret"));
    recap_mw->verification_client(ok_verifier(R"({"success":false,"error-codes":["invalid-input-secret"]})", &verifier_called));

    run_recaptcha(recap_mw, recaptcha_request("mocked_token_google_error"));

    EXPECT_TRUE(verifier_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_NE(body().find("invalid-input-secret"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(RecaptchaMiddlewareTest, MalformedVerificationJsonRejectsGracefully) {
    // Google returns 200 but a non-JSON body: parse failure ⇒ success=false ⇒ 403, no crash.
    // The middleware still persists the (failed) RecaptchaResult into the context before
    // rejecting, so the recovery lifecycle hook observes it even though the terminal handler
    // never runs on the 403 path. error_codes carries the parse-failure reason.
    bool verifier_called = false;
    auto recap_mw        = qb::http::recaptcha_middleware<MockRecaptchaSession>(qb::http::RecaptchaOptions("test_secret"));
    recap_mw->verification_client(ok_verifier("this is not json {{{", &verifier_called));

    run_recaptcha(recap_mw, recaptcha_request("malformed_response_token"));

    EXPECT_TRUE(verifier_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_FALSE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_recaptcha_result_in_context.has_value());
    EXPECT_FALSE(_session->_recaptcha_result_in_context->success);
    EXPECT_NE(_session->_recaptcha_result_in_context->error_codes.find("JSON parsing error"), std::string::npos);
}

TEST_F(RecaptchaMiddlewareTest, Non200VerifierResponseRejectsAsTransportFailure) {
    // Google transport failure: a non-200 status ⇒ success=false with an HTTP-error code ⇒ 403.
    // As with the malformed-JSON path, the failed RecaptchaResult is stored into the context
    // before the rejection, so the recovery lifecycle hook observes it on the 403 path.
    bool verifier_called = false;
    auto recap_mw        = qb::http::recaptcha_middleware<MockRecaptchaSession>(qb::http::RecaptchaOptions("test_secret"));
    recap_mw->verification_client([&](qb::http::Request request, VCallback cb) {
        verifier_called = true;
        qb::http::Response response;
        response.status() = qb::http::status::SERVICE_UNAVAILABLE; // 503 from Google edge
        response.body()   = R"({"success":true,"score":0.99})";    // body ignored on non-200
        cb(qb::http::async::Reply{std::move(request), std::move(response)});
    });

    run_recaptcha(recap_mw, recaptcha_request("transport_fail_token"));

    EXPECT_TRUE(verifier_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_FALSE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_recaptcha_result_in_context.has_value());
    EXPECT_FALSE(_session->_recaptcha_result_in_context->success);
    EXPECT_NE(_session->_recaptcha_result_in_context->error_codes.find("HTTP error"), std::string::npos);
}

} // namespace

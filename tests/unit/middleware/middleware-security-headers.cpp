/**
 * @file qbm/http/tests/unit/middleware/middleware-security-headers.cpp
 * @brief Unit tests for qb::http::SecurityHeadersMiddleware.
 *
 * Drives the real qb::http::Router<Session> synchronously over the shared
 * capturing MockMiddlewareSession (no qb::Main, no socket, no event loop): a
 * synthetic Request is routed and the finalized Response's security headers are
 * asserted. Coverage walks every shipped header toggle (HSTS, X-Content-Type,
 * X-Frame, CSP[+report-only], Referrer-Policy, Permissions-Policy, the three
 * Cross-Origin policies, X-Permitted-Cross-Domain-Policies), the HTTPS-only HSTS
 * conditional, header ordering / canonical-casing stability, middleware-wins
 * precedence, options mutability, and the `csp_nonce` crypto path.
 *
 * The `#ifdef QB_HAS_SSL` split is intentional and legitimate: `with_csp_nonce`
 * links qb::crypto's secure-random generator, so the file builds without SSL
 * but the nonce *factory* throws std::logic_error there (asserted in the #else
 * branch). The file is registered `REQUIRES ssl` only for the nonce cases.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "../../shared/middleware_test_fixture.h"

#include "../middleware/security_headers.h"
#include "../routing/middleware.h"

using qb::http::test::MockMiddlewareSession;

namespace {

/**
 * @brief Fixture for SecurityHeadersMiddleware.
 *
 * Reuses the shared MiddlewareTestFixture (fresh session + router per test) and
 * adds a scheme-aware request factory plus header presence/value/absence
 * assertions — security headers (notably HSTS) are scheme-conditional, so the
 * request URI must carry an explicit `http`/`https` scheme.
 */
class SecurityHeadersMiddlewareTest : public qb::http::test::MiddlewareTestFixture<MockMiddlewareSession> {
protected:
    qb::http::Request
    scheme_request(qb::http::method method_val = qb::http::method::GET, const std::string &target_path = "/test",
                   const std::string &scheme = "http") {
        qb::http::Request req;
        req.method()          = method_val;
        const std::string url = scheme + "://localhost" + target_path;
        try {
            req.uri() = qb::io::uri(url);
        } catch (const std::exception &e) {
            ADD_FAILURE() << "URI parse failure: " << url << " (" << e.what() << ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        req.major_version = 1;
        req.minor_version = 1;
        return req;
    }

    qb::http::RouteHandlerFn<MockMiddlewareSession>
    body_handler() {
        return [this](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
            _session->_final_handler_called = true;
            ctx->response().status()        = qb::http::status::OK;
            ctx->response().body()          = "Test body";
            ctx->complete();
        };
    }

    /** @brief Wires @p mw ahead of @p handler on /test, compiles, routes one request. */
    void
    run(std::shared_ptr<qb::http::IMiddleware<MockMiddlewareSession>> mw, qb::http::Request request,
        qb::http::RouteHandlerFn<MockMiddlewareSession> handler) {
        _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
        _router->use(std::move(mw));
        _router->get("/test", std::move(handler));
        _router->compile();
        _session->reset();
        _router->route(_session, std::move(request));
    }

    /** @brief Default-handler convenience overload. */
    void
    run(std::shared_ptr<qb::http::IMiddleware<MockMiddlewareSession>> mw, qb::http::Request request) {
        run(std::move(mw), std::move(request), body_handler());
    }

    void
    expect_header_value(const std::string &name, const std::string &expected) {
        ASSERT_TRUE(_session->_response.has_header(name)) << "Header " << name << " not found.";
        EXPECT_EQ(_session->_response.header(name), expected) << "Header " << name << " mismatch.";
    }

    void
    expect_header_absent(const std::string &name) {
        EXPECT_FALSE(_session->_response.has_header(name)) << "Header " << name << " should not be present.";
    }
};

// --- Default-secure header set --------------------------------------------

TEST_F(SecurityHeadersMiddlewareTest, AppliesSecureDefaultHeadersForHTTP) {
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(), scheme_request(qb::http::method::GET, "/test", "http"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);

    const auto &d = qb::http::SecurityHeadersOptions::secure_defaults();

    expect_header_absent("Strict-Transport-Security"); // HSTS is HTTPS-only
    expect_header_value("X-Content-Type-Options", "nosniff");
    expect_header_value("X-Frame-Options", *d.get_x_frame_options_value());
    expect_header_value("Content-Security-Policy", *d.get_content_security_policy_value());
    expect_header_value("Referrer-Policy", *d.get_referrer_policy_value());
    expect_header_value("Cross-Origin-Opener-Policy", *d.get_coop_value());
    expect_header_value("X-Permitted-Cross-Domain-Policies", *d.get_x_permitted_cross_domain_policies_value());

    expect_header_absent("Content-Security-Policy-Report-Only");
    expect_header_absent("Permissions-Policy");
    expect_header_absent("Cross-Origin-Embedder-Policy");
    expect_header_absent("Cross-Origin-Resource-Policy");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesSecureDefaultHeadersForHTTPSIncludesHSTS) {
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(), scheme_request(qb::http::method::GET, "/test", "https"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);

    const auto &d = qb::http::SecurityHeadersOptions::secure_defaults();

    expect_header_value("Strict-Transport-Security", *d.get_hsts_value());
    expect_header_value("X-Content-Type-Options", "nosniff");
    expect_header_value("X-Frame-Options", *d.get_x_frame_options_value());
    expect_header_value("Content-Security-Policy", *d.get_content_security_policy_value());
    expect_header_value("Referrer-Policy", *d.get_referrer_policy_value());
    expect_header_value("Cross-Origin-Opener-Policy", *d.get_coop_value());
    expect_header_value("X-Permitted-Cross-Domain-Policies", *d.get_x_permitted_cross_domain_policies_value());
}

// --- Per-header apply / remove --------------------------------------------

TEST_F(SecurityHeadersMiddlewareTest, AppliesCustomHSTS) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_hsts("max-age=600; includeSubDomains");
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request(qb::http::method::GET, "/test", "https"));
    expect_header_value("Strict-Transport-Security", "max-age=600; includeSubDomains");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesHSTS) {
    auto opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.without_hsts();
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request(qb::http::method::GET, "/test", "https"));
    expect_header_absent("Strict-Transport-Security");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesXContentTypeOptions) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_x_content_type_options_nosniff(true);
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_value("X-Content-Type-Options", "nosniff");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesXContentTypeOptions) {
    auto opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.with_x_content_type_options_nosniff(false);
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_absent("X-Content-Type-Options");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCustomXFrameOptions) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_x_frame_options("DENY");
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_value("X-Frame-Options", "DENY");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesXFrameOptions) {
    auto opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.without_x_frame_options();
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_absent("X-Frame-Options");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCustomCSP) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_content_security_policy("default-src 'none'");
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_value("Content-Security-Policy", "default-src 'none'");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesCSP) {
    auto opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.without_content_security_policy();
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_absent("Content-Security-Policy");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCSPReportOnly) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_content_security_policy_report_only("default-src 'self'; report-uri /csp-violations");
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_value("Content-Security-Policy-Report-Only", "default-src 'self'; report-uri /csp-violations");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesCSPReportOnly) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_content_security_policy_report_only("value");
    opts.without_content_security_policy_report_only();
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_absent("Content-Security-Policy-Report-Only");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCustomReferrerPolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_referrer_policy("no-referrer");
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_value("Referrer-Policy", "no-referrer");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesReferrerPolicy) {
    auto opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.without_referrer_policy();
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_absent("Referrer-Policy");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesPermissionsPolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_permissions_policy("geolocation=(self), microphone=()");
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_value("Permissions-Policy", "geolocation=(self), microphone=()");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesPermissionsPolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_permissions_policy("value");
    opts.without_permissions_policy();
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_absent("Permissions-Policy");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCrossOriginOpenerPolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_cross_origin_opener_policy("unsafe-none");
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_value("Cross-Origin-Opener-Policy", "unsafe-none");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesCrossOriginOpenerPolicy) {
    auto opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.without_cross_origin_opener_policy();
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_absent("Cross-Origin-Opener-Policy");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCrossOriginEmbedderPolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_cross_origin_embedder_policy("require-corp");
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_value("Cross-Origin-Embedder-Policy", "require-corp");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesCrossOriginEmbedderPolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_cross_origin_embedder_policy("value");
    opts.without_cross_origin_embedder_policy();
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_absent("Cross-Origin-Embedder-Policy");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCrossOriginResourcePolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_cross_origin_resource_policy("same-site");
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_value("Cross-Origin-Resource-Policy", "same-site");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesCrossOriginResourcePolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_cross_origin_resource_policy("value");
    opts.without_cross_origin_resource_policy();
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_absent("Cross-Origin-Resource-Policy");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesXPermittedCrossDomainPolicies) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_x_permitted_cross_domain_policies("master-only");
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_value("X-Permitted-Cross-Domain-Policies", "master-only");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesXPermittedCrossDomainPolicies) {
    auto opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.without_x_permitted_cross_domain_policies();
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    expect_header_absent("X-Permitted-Cross-Domain-Policies");
}

// --- HSTS scheme conditional -----------------------------------------------

TEST_F(SecurityHeadersMiddlewareTest, ConditionalHSTSOnlyOnHTTPS) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_hsts("max-age=31536000");
    auto mw = qb::http::security_headers_middleware<MockMiddlewareSession>(opts);

    _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
    _router->use(mw);
    _router->get("/test_http", body_handler());
    _router->get("/test_https", body_handler());
    _router->compile();

    _session->reset();
    _router->route(_session, scheme_request(qb::http::method::GET, "/test_http", "http"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    expect_header_absent("Strict-Transport-Security");

    _session->reset();
    _router->route(_session, scheme_request(qb::http::method::GET, "/test_https", "https"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    expect_header_value("Strict-Transport-Security", "max-age=31536000");
}

// --- Header ordering / canonical-casing stability --------------------------
//
// Two requests with the same options must produce byte-identical security-header
// sets — both the set of names and (the icase map being stable) their canonical
// casing. This pins that the middleware does not reorder or recase across runs.

TEST_F(SecurityHeadersMiddlewareTest, HeaderSetIsStableAndCanonicallyCasedAcrossRequests) {
    auto opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.with_permissions_policy("geolocation=()");
    auto mw = qb::http::security_headers_middleware<MockMiddlewareSession>(opts);

    static const std::vector<std::string> kSecurityHeaders = {
        "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options",
        "Content-Security-Policy",   "Referrer-Policy",        "Permissions-Policy",
        "Cross-Origin-Opener-Policy", "X-Permitted-Cross-Domain-Policies"};

    auto snapshot = [&](void) {
        std::vector<std::pair<std::string, std::string>> out;
        for (const std::string &name : kSecurityHeaders) {
            if (_session->_response.has_header(name)) {
                out.emplace_back(name, std::string(_session->_response.header(name)));
            }
        }
        return out;
    };

    run(mw, scheme_request(qb::http::method::GET, "/test", "https"));
    const auto first = snapshot();
    // All eight defaults (incl. HSTS over https + Permissions-Policy) must be present.
    EXPECT_EQ(first.size(), kSecurityHeaders.size());

    // Re-run on the SAME mw instance: identical name set, identical values,
    // identical canonical casing (icase map lookups by the canonical name hit).
    _session->reset();
    _router->route(_session, scheme_request(qb::http::method::GET, "/test", "https"));
    const auto second = snapshot();
    EXPECT_EQ(first, second);

    // Canonical-casing probe: requesting via a differently-cased name must still
    // hit (icase map), proving the stored name is the canonical mixed-case form.
    EXPECT_TRUE(_session->_response.has_header(std::string("content-security-policy")));
    EXPECT_TRUE(_session->_response.has_header(std::string("STRICT-TRANSPORT-SECURITY")));
    EXPECT_EQ(_session->_response.header(std::string("x-frame-options")), *opts.get_x_frame_options_value());
}

// --- csp_nonce (crypto-dependent) ------------------------------------------

#ifdef QB_HAS_SSL
TEST_F(SecurityHeadersMiddlewareTest, CSPNonceGeneratedAndInContext) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_csp_nonce(true);

    std::string captured_nonce;
    run(
        qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request(qb::http::method::GET, "/test", "http"),
        [this, &captured_nonce](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
            _session->_final_handler_called = true;
            auto nonce_opt                  = ctx->template get<std::string>("csp_nonce");
            ASSERT_TRUE(nonce_opt.has_value()) << "CSP Nonce not found in context properties";
            captured_nonce = *nonce_opt;
            EXPECT_FALSE(captured_nonce.empty());
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    ASSERT_FALSE(captured_nonce.empty());

    const std::string expected_csp = "default-src 'self'; "
                                     "script-src 'self' 'nonce-" + captured_nonce + "' 'strict-dynamic'; "
                                     "style-src 'self' 'nonce-" + captured_nonce + "'; "
                                     "object-src 'none'; base-uri 'self'; form-action 'self';";
    expect_header_value("Content-Security-Policy", expected_csp);
}

TEST_F(SecurityHeadersMiddlewareTest, CSPNonceIsFreshPerRequest) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_csp_nonce(true);
    auto mw = qb::http::security_headers_middleware<MockMiddlewareSession>(opts);

    std::string nonce_a;
    std::string nonce_b;
    auto capture = [this](std::string &out) {
        return [this, &out](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
            _session->_final_handler_called = true;
            auto n                          = ctx->template get<std::string>("csp_nonce");
            ASSERT_TRUE(n.has_value());
            out = *n;
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        };
    };

    _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
    _router->use(mw);
    _router->get("/a", capture(nonce_a));
    _router->get("/b", capture(nonce_b));
    _router->compile();

    _session->reset();
    _router->route(_session, scheme_request(qb::http::method::GET, "/a", "http"));
    _session->reset();
    _router->route(_session, scheme_request(qb::http::method::GET, "/b", "http"));

    EXPECT_FALSE(nonce_a.empty());
    EXPECT_FALSE(nonce_b.empty());
    EXPECT_NE(nonce_a, nonce_b) << "Nonces must be unique per request (CSP replay defence).";
}

TEST_F(SecurityHeadersMiddlewareTest, CSPNonceWithUserProvidedCSP) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_csp_nonce(true).with_content_security_policy("custom-csp 'self'; script-src 'unsafe-inline'");

    std::string captured;
    run(
        qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request(qb::http::method::GET, "/test", "http"),
        [this, &captured](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
            _session->_final_handler_called = true;
            auto n                          = ctx->template get<std::string>("csp_nonce");
            ASSERT_TRUE(n.has_value()) << "CSP Nonce must still be exposed even with a custom CSP";
            captured = *n;
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_FALSE(captured.empty());
    // The user-provided CSP must win over the default nonce-based policy.
    expect_header_value("Content-Security-Policy", "custom-csp 'self'; script-src 'unsafe-inline'");
}
#else
TEST_F(SecurityHeadersMiddlewareTest, CSPNonceRequiresSSL) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_csp_nonce(true);
    EXPECT_THROW((void) qb::http::security_headers_middleware<MockMiddlewareSession>(opts), std::logic_error);
}
#endif

TEST_F(SecurityHeadersMiddlewareTest, CSPNonceDisabledNoNonceInContextOrDefaultCSP) {
    auto opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.with_csp_nonce(false);
    opts.without_content_security_policy();

    run(
        qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request(qb::http::method::GET, "/test", "http"),
        [this](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
            _session->_final_handler_called = true;
            EXPECT_FALSE(ctx->template get<std::string>("csp_nonce").has_value());
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });

    EXPECT_TRUE(_session->_final_handler_called);
    expect_header_absent("Content-Security-Policy");
}

// --- Precedence, edge values, mutability -----------------------------------

TEST_F(SecurityHeadersMiddlewareTest, MiddlewareOverwritesHandlerSetHeader) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_x_frame_options("SAMEORIGIN");

    run(
        qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request(),
        [this](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
            _session->_final_handler_called = true;
            ctx->response().set_header("X-Frame-Options", "DENY"); // handler tries DENY...
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });

    EXPECT_TRUE(_session->_final_handler_called);
    expect_header_value("X-Frame-Options", "SAMEORIGIN"); // ...middleware's value wins.
}

TEST_F(SecurityHeadersMiddlewareTest, OptionWithEmptyStringValue) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_x_frame_options("");
    run(qb::http::security_headers_middleware<MockMiddlewareSession>(opts), scheme_request());
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    expect_header_value("X-Frame-Options", "");
}

TEST_F(SecurityHeadersMiddlewareTest, OptionsCanBeUpdated) {
    auto mw = qb::http::security_headers_middleware<MockMiddlewareSession>();

    _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
    _router->use(mw);
    _router->get("/default", body_handler());
    _router->get("/updated", body_handler());
    _router->compile();

    _session->reset();
    _router->route(_session, scheme_request(qb::http::method::GET, "/default", "https"));
    expect_header_value("X-Frame-Options", *qb::http::SecurityHeadersOptions::secure_defaults().get_x_frame_options_value());
    expect_header_absent("Permissions-Policy");

    qb::http::SecurityHeadersOptions new_opts;
    new_opts.with_x_frame_options("DENY").with_permissions_policy("fullscreen=()");

    auto concrete = std::dynamic_pointer_cast<qb::http::SecurityHeadersMiddleware<MockMiddlewareSession>>(mw);
    ASSERT_NE(concrete, nullptr);
    concrete->update_options(new_opts);

    _session->reset();
    _router->route(_session, scheme_request(qb::http::method::GET, "/updated", "https"));
    expect_header_value("X-Frame-Options", "DENY");
    expect_header_value("Permissions-Policy", "fullscreen=()");
    expect_header_absent("Strict-Transport-Security"); // not in new_opts
    expect_header_absent("Content-Security-Policy");   // not in new_opts
}

TEST_F(SecurityHeadersMiddlewareTest, EmptyOptionsMeansNoHeaders) {
    qb::http::SecurityHeadersOptions empty_opts;
    empty_opts.with_x_content_type_options_nosniff(false);

    run(qb::http::security_headers_middleware<MockMiddlewareSession>(empty_opts), scheme_request(qb::http::method::GET, "/test", "https"));

    for (const char *name : {"Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy",
                             "Content-Security-Policy-Report-Only", "Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy",
                             "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy", "X-Permitted-Cross-Domain-Policies"}) {
        expect_header_absent(std::string(name));
    }
}

TEST_F(SecurityHeadersMiddlewareTest, MiddlewareNameIsCorrect) {
    EXPECT_EQ(qb::http::security_headers_middleware<MockMiddlewareSession>()->name(), "SecurityHeadersMiddleware");
    EXPECT_EQ(qb::http::security_headers_middleware<MockMiddlewareSession>(qb::http::SecurityHeadersOptions::secure_defaults(),
                                                                           "MyCustomSecurityHeaders")
                  ->name(),
              "MyCustomSecurityHeaders");
}

TEST_F(SecurityHeadersMiddlewareTest, GetOptionsReturnsCurrentOptions) {
    qb::http::SecurityHeadersOptions initial;
    initial.with_hsts("max-age=100");

    auto mw       = qb::http::security_headers_middleware<MockMiddlewareSession>(initial);
    auto concrete = std::dynamic_pointer_cast<qb::http::SecurityHeadersMiddleware<MockMiddlewareSession>>(mw);
    ASSERT_NE(concrete, nullptr);

    const auto &opts1 = concrete->get_options();
    ASSERT_TRUE(opts1.get_hsts_value().has_value());
    EXPECT_EQ(*opts1.get_hsts_value(), "max-age=100");
    EXPECT_FALSE(opts1.get_set_x_content_type_options_nosniff());

    qb::http::SecurityHeadersOptions updated;
    updated.with_x_content_type_options_nosniff(true);
    concrete->update_options(updated);

    const auto &opts2 = concrete->get_options();
    EXPECT_FALSE(opts2.get_hsts_value().has_value());
    EXPECT_TRUE(opts2.get_set_x_content_type_options_nosniff());
}

} // namespace

#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/security_headers.h"
#include "../routing/middleware.h"

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <sstream> // For ostringstream in session mock

// --- Mock Session for SecurityHeadersMiddleware Tests ---
struct MockSecuritySession {
    qb::http::Response _response;
    std::string _session_id_str = "security_headers_test_session";
    std::ostringstream _trace;
    bool _final_handler_called = false;

    qb::http::Response &get_response_ref() { return _response; }

    MockSecuritySession &operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    void reset() {
        _response = qb::http::Response();
        _trace.str("");
        _trace.clear();
        _final_handler_called = false;
    }
};

// --- Test Fixture for SecurityHeadersMiddleware --- 
class SecurityHeadersMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockSecuritySession> _session;
    std::unique_ptr<qb::http::Router<MockSecuritySession> > _router;

    void SetUp() override {
        _session = std::make_shared<MockSecuritySession>();
        _router = std::make_unique<qb::http::Router<MockSecuritySession> >();
    }

    qb::http::Request create_request(qb::http::method method_val = qb::http::method::GET,
                                     const std::string &target_path = "/test",
                                     const std::string &scheme = "http") {
        qb::http::Request req;
        req.method() = method_val;
        try {
            req.uri() = qb::io::uri(scheme + "://localhost" + target_path);
        } catch (const std::exception &e) {
            ADD_FAILURE() << "URI parse failure: " << scheme << "://localhost" << target_path << " (" << e.what() <<
 ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        return req;
    }

    qb::http::RouteHandlerFn<MockSecuritySession> basic_success_handler() {
        return [this](std::shared_ptr<qb::http::Context<MockSecuritySession> > ctx) {
            _session->_final_handler_called = true;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "Test body";
            ctx->complete();
        };
    }

    void configure_router_with_mw(std::shared_ptr<qb::http::IMiddleware<MockSecuritySession> > mw) {
        _router->use(mw);
        _router->get("/test", basic_success_handler());
        _router->compile();
    }

    void configure_router_with_mw_and_handler(
        std::shared_ptr<qb::http::IMiddleware<MockSecuritySession> > mw,
        qb::http::RouteHandlerFn<MockSecuritySession> handler) {
        _router->use(mw);
        _router->get("/test", handler);
        _router->compile();
    }

    void make_request(qb::http::Request request) {
        _session->reset(); // Ensure session is clean before each request
        _router->route(_session, std::move(request));
    }

    void expect_header_value(const std::string &header_name, const std::string &expected_value) {
        EXPECT_TRUE(_session->_response.has_header(header_name)) << "Header " << header_name << " not found.";
        if (_session->_response.has_header(header_name)) {
            EXPECT_EQ(_session->_response.header(header_name), expected_value)
                << "Header " << header_name << " has value '" << _session->_response.header(header_name)
                << "', expected '" << expected_value << "'.";
        }
    }

    void expect_header_absent(const std::string &header_name) {
        EXPECT_FALSE(_session->_response.has_header(header_name)) << "Header " << header_name <<
 " should not be present.";
    }
};

// Test default secure options
TEST_F(SecurityHeadersMiddlewareTest, AppliesSecureDefaultHeadersForHTTP) {
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>();
    _router->use(sh_mw);
    _router->get("/test_http_defaults", basic_success_handler());
    _router->compile();

    make_request(create_request(qb::http::method::GET, "/test_http_defaults", "http"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);

    const auto &default_opts = qb::http::SecurityHeadersOptions::secure_defaults();

    expect_header_absent("Strict-Transport-Security");
    expect_header_value("X-Content-Type-Options", "nosniff");
    expect_header_value("X-Frame-Options", *default_opts.get_x_frame_options_value());
    expect_header_value("Content-Security-Policy", *default_opts.get_content_security_policy_value());
    expect_header_value("Referrer-Policy", *default_opts.get_referrer_policy_value());
    expect_header_value("Cross-Origin-Opener-Policy", *default_opts.get_coop_value());
    expect_header_value("X-Permitted-Cross-Domain-Policies",
                        *default_opts.get_x_permitted_cross_domain_policies_value());

    // Headers not set by default
    expect_header_absent("Content-Security-Policy-Report-Only");
    expect_header_absent("Permissions-Policy");
    expect_header_absent("Cross-Origin-Embedder-Policy");
    expect_header_absent("Cross-Origin-Resource-Policy");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesSecureDefaultHeadersForHTTPSIncludesHSTS) {
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>();
    _router->use(sh_mw);
    _router->get("/test_https_defaults", basic_success_handler());
    _router->compile();

    make_request(create_request(qb::http::method::GET, "/test_https_defaults", "https"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);

    const auto &default_opts = qb::http::SecurityHeadersOptions::secure_defaults();

    expect_header_value("Strict-Transport-Security", *default_opts.get_hsts_value());
    expect_header_value("X-Content-Type-Options", "nosniff");
    expect_header_value("X-Frame-Options", *default_opts.get_x_frame_options_value());
    expect_header_value("Content-Security-Policy", *default_opts.get_content_security_policy_value());
    expect_header_value("Referrer-Policy", *default_opts.get_referrer_policy_value());
    expect_header_value("Cross-Origin-Opener-Policy", *default_opts.get_coop_value());
    expect_header_value("X-Permitted-Cross-Domain-Policies",
                        *default_opts.get_x_permitted_cross_domain_policies_value());
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCustomHSTS) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_hsts("max-age=600; includeSubDomains");
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request(qb::http::method::GET, "/test", "https"));
    expect_header_value("Strict-Transport-Security", "max-age=600; includeSubDomains");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesHSTS) {
    qb::http::SecurityHeadersOptions opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.without_hsts();
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_absent("Strict-Transport-Security");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesXContentTypeOptions) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_x_content_type_options_nosniff(true); // Default is true in secure_defaults, but test explicit set
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_value("X-Content-Type-Options", "nosniff");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesXContentTypeOptions) {
    qb::http::SecurityHeadersOptions opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.with_x_content_type_options_nosniff(false);
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_absent("X-Content-Type-Options");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCustomXFrameOptions) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_x_frame_options("DENY");
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_value("X-Frame-Options", "DENY");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesXFrameOptions) {
    qb::http::SecurityHeadersOptions opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.without_x_frame_options();
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_absent("X-Frame-Options");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCustomCSP) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_content_security_policy("default-src 'none'");
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_value("Content-Security-Policy", "default-src 'none'");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesCSP) {
    qb::http::SecurityHeadersOptions opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.without_content_security_policy();
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_absent("Content-Security-Policy");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCSPReportOnly) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_content_security_policy_report_only("default-src 'self'; report-uri /csp-violations");
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_value("Content-Security-Policy-Report-Only", "default-src 'self'; report-uri /csp-violations");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesCSPReportOnly) {
    qb::http::SecurityHeadersOptions opts; // Start with empty
    opts.with_content_security_policy_report_only("value"); // Set it
    opts.without_content_security_policy_report_only(); // Then remove it
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_absent("Content-Security-Policy-Report-Only");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCustomReferrerPolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_referrer_policy("no-referrer");
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_value("Referrer-Policy", "no-referrer");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesReferrerPolicy) {
    qb::http::SecurityHeadersOptions opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.without_referrer_policy();
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_absent("Referrer-Policy");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesPermissionsPolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_permissions_policy("geolocation=(self), microphone=()");
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_value("Permissions-Policy", "geolocation=(self), microphone=()");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesPermissionsPolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_permissions_policy("value");
    opts.without_permissions_policy();
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_absent("Permissions-Policy");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCrossOriginOpenerPolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_cross_origin_opener_policy("unsafe-none");
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_value("Cross-Origin-Opener-Policy", "unsafe-none");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesCrossOriginOpenerPolicy) {
    qb::http::SecurityHeadersOptions opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.without_cross_origin_opener_policy();
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_absent("Cross-Origin-Opener-Policy");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCrossOriginEmbedderPolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_cross_origin_embedder_policy("require-corp");
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_value("Cross-Origin-Embedder-Policy", "require-corp");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesCrossOriginEmbedderPolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_cross_origin_embedder_policy("value");
    opts.without_cross_origin_embedder_policy();
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_absent("Cross-Origin-Embedder-Policy");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesCrossOriginResourcePolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_cross_origin_resource_policy("same-site");
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_value("Cross-Origin-Resource-Policy", "same-site");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesCrossOriginResourcePolicy) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_cross_origin_resource_policy("value");
    opts.without_cross_origin_resource_policy();
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_absent("Cross-Origin-Resource-Policy");
}

TEST_F(SecurityHeadersMiddlewareTest, AppliesXPermittedCrossDomainPolicies) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_x_permitted_cross_domain_policies("master-only");
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_value("X-Permitted-Cross-Domain-Policies", "master-only");
}

TEST_F(SecurityHeadersMiddlewareTest, RemovesXPermittedCrossDomainPolicies) {
    qb::http::SecurityHeadersOptions opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.without_x_permitted_cross_domain_policies();
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());
    expect_header_absent("X-Permitted-Cross-Domain-Policies");
}

TEST_F(SecurityHeadersMiddlewareTest, ConditionalHSTSOnlyOnHTTPS) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_hsts("max-age=31536000");
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    _router->use(sh_mw);
    _router->get("/test_http", basic_success_handler());
    _router->get("/test_https", basic_success_handler());
    _router->compile();

    // HTTP request
    make_request(create_request(qb::http::method::GET, "/test_http", "http"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    expect_header_absent("Strict-Transport-Security");

    _session->reset(); // Reset session before next request

    // HTTPS request
    make_request(create_request(qb::http::method::GET, "/test_https", "https"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    expect_header_value("Strict-Transport-Security", "max-age=31536000");
}

TEST_F(SecurityHeadersMiddlewareTest, CSPNonceGeneratedAndInContext) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_csp_nonce(true);

    std::string captured_nonce;

    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    _router->use(sh_mw);
    _router->get("/test_nonce", [this, &captured_nonce](auto ctx) {
        _session->_final_handler_called = true;
        auto nonce_opt = ctx->template get<std::string>("csp_nonce");
        EXPECT_TRUE(nonce_opt.has_value()) << "CSP Nonce not found in context properties";
        if (nonce_opt) {
            captured_nonce = *nonce_opt;
            EXPECT_FALSE(captured_nonce.empty()) << "CSP Nonce in context is empty";
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();

    make_request(create_request(qb::http::method::GET, "/test_nonce", "http"));
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);

    ASSERT_FALSE(captured_nonce.empty());
    std::string expected_csp =
            "default-src 'self'; "
            "script-src 'self' 'nonce-" + captured_nonce + "' 'strict-dynamic'; "
            "style-src 'self' 'nonce-" + captured_nonce + "'; "
            "object-src 'none'; base-uri 'self'; form-action 'self';";
    expect_header_value("Content-Security-Policy", expected_csp);
}

TEST_F(SecurityHeadersMiddlewareTest, CSPNonceWithUserProvidedCSP) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_csp_nonce(true)
            .with_content_security_policy("custom-csp 'self'; script-src 'unsafe-inline'");

    std::string captured_nonce_in_handler;

    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    _router->use(sh_mw);
    _router->get("/test_nonce_custom_csp", [this, &captured_nonce_in_handler](auto ctx) {
        _session->_final_handler_called = true;
        auto nonce_opt = ctx->template get<std::string>("csp_nonce");
        EXPECT_TRUE(nonce_opt.has_value()) << "CSP Nonce not found in context properties even with custom CSP";
        if (nonce_opt) {
            captured_nonce_in_handler = *nonce_opt;
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();

    make_request(create_request(qb::http::method::GET, "/test_nonce_custom_csp", "http"));
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_FALSE(captured_nonce_in_handler.empty());

    // Middleware should use the user-provided CSP, not the default nonce-based one
    expect_header_value("Content-Security-Policy", "custom-csp 'self'; script-src 'unsafe-inline'");
}

TEST_F(SecurityHeadersMiddlewareTest, CSPNonceDisabledNoNonceInContextOrDefaultCSP) {
    qb::http::SecurityHeadersOptions opts = qb::http::SecurityHeadersOptions::secure_defaults();
    opts.with_csp_nonce(false);
    opts.without_content_security_policy();

    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    _router->use(sh_mw);
    _router->get("/test_no_nonce", [this](auto ctx) {
        _session->_final_handler_called = true;
        auto nonce_opt = ctx->template get<std::string>("csp_nonce");
        EXPECT_FALSE(nonce_opt.has_value()) << "CSP Nonce should not be in context if disabled";
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();

    make_request(create_request(qb::http::method::GET, "/test_no_nonce", "http"));
    EXPECT_TRUE(_session->_final_handler_called);
    expect_header_absent("Content-Security-Policy"); // No CSP should be set if nonce disabled and no default
}

TEST_F(SecurityHeadersMiddlewareTest, MiddlewareOverwritesHandlerSetHeader) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_x_frame_options("SAMEORIGIN");
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);

    _router->use(sh_mw);
    _router->get("/test_overwrite", [this](auto ctx) {
        _session->_final_handler_called = true;
        ctx->response().set_header("X-Frame-Options", "DENY");
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();

    make_request(create_request(qb::http::method::GET, "/test_overwrite"));
    EXPECT_TRUE(_session->_final_handler_called);
    expect_header_value("X-Frame-Options", "SAMEORIGIN"); // Middleware's value should win
}

TEST_F(SecurityHeadersMiddlewareTest, OptionWithEmptyStringValue) {
    qb::http::SecurityHeadersOptions opts;
    opts.with_x_frame_options("");
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(opts);
    _router->use(sh_mw);
    _router->get("/test_empty_option_val", basic_success_handler());
    _router->compile();

    make_request(create_request(qb::http::method::GET, "/test_empty_option_val"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    expect_header_value("X-Frame-Options", "");
}

TEST_F(SecurityHeadersMiddlewareTest, OptionsCanBeUpdated) {
    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>();
    _router->use(sh_mw);
    _router->get("/test_default_opts", basic_success_handler());
    _router->get("/test_updated_opts", basic_success_handler());
    _router->compile();

    // First request with default options
    make_request(create_request(qb::http::method::GET, "/test_default_opts", "https"));
    expect_header_value("X-Frame-Options",
                        *qb::http::SecurityHeadersOptions::secure_defaults().get_x_frame_options_value());
    expect_header_absent("Permissions-Policy");

    // Update options
    qb::http::SecurityHeadersOptions new_opts;
    new_opts.with_x_frame_options("DENY")
            .with_permissions_policy("fullscreen=()");

    // Need to get the concrete type to call update_options
    auto concrete_mw = std::dynamic_pointer_cast<qb::http::SecurityHeadersMiddleware<MockSecuritySession> >(sh_mw);
    ASSERT_NE(concrete_mw, nullptr);
    concrete_mw->update_options(new_opts);

    // Second request, should use new options
    make_request(create_request(qb::http::method::GET, "/test_updated_opts"));

    expect_header_value("X-Frame-Options", "DENY");
    expect_header_value("Permissions-Policy", "fullscreen=()");
    // Check a default header is no longer there if not in new_opts
    expect_header_absent("Strict-Transport-Security");
}

TEST_F(SecurityHeadersMiddlewareTest, EmptyOptionsMeansNoHeaders) {
    qb::http::SecurityHeadersOptions empty_opts;
    // Explicitly ensure no defaults are somehow sneaking in if an empty one is passed.
    // For example, X-Content-Type-Options: nosniff is a bool.
    empty_opts.with_x_content_type_options_nosniff(false);

    auto sh_mw = qb::http::security_headers_middleware<MockSecuritySession>(empty_opts);
    configure_router_with_mw(sh_mw);
    make_request(create_request());

    expect_header_absent("Strict-Transport-Security");
    expect_header_absent("X-Content-Type-Options");
    expect_header_absent("X-Frame-Options");
    expect_header_absent("Content-Security-Policy");
    expect_header_absent("Content-Security-Policy-Report-Only");
    expect_header_absent("Referrer-Policy");
    expect_header_absent("Permissions-Policy");
    expect_header_absent("Cross-Origin-Opener-Policy");
    expect_header_absent("Cross-Origin-Embedder-Policy");
    expect_header_absent("Cross-Origin-Resource-Policy");
    expect_header_absent("X-Permitted-Cross-Domain-Policies");
}

TEST_F(SecurityHeadersMiddlewareTest, MiddlewareNameIsCorrect) {
    auto mw_default_name = qb::http::security_headers_middleware<MockSecuritySession>();
    EXPECT_EQ(mw_default_name->name(), "SecurityHeadersMiddleware");

    auto mw_custom_name = qb::http::security_headers_middleware<MockSecuritySession>(
        qb::http::SecurityHeadersOptions::secure_defaults(),
        "MyCustomSecurityHeaders"
    );
    EXPECT_EQ(mw_custom_name->name(), "MyCustomSecurityHeaders");
}

// Test that get_options returns the current options
TEST_F(SecurityHeadersMiddlewareTest, GetOptionsReturnsCurrentOptions) {
    qb::http::SecurityHeadersOptions initial_opts;
    initial_opts.with_hsts("max-age=100");

    auto mw = qb::http::security_headers_middleware<MockSecuritySession>(initial_opts);
    auto concrete_mw = std::dynamic_pointer_cast<qb::http::SecurityHeadersMiddleware<MockSecuritySession> >(mw);
    ASSERT_NE(concrete_mw, nullptr);

    const auto &retrieved_opts1 = concrete_mw->get_options();
    EXPECT_EQ(retrieved_opts1.get_hsts_value(), "max-age=100");
    EXPECT_FALSE(retrieved_opts1.get_set_x_content_type_options_nosniff()); // Should be default false

    qb::http::SecurityHeadersOptions updated_opts;
    updated_opts.with_x_content_type_options_nosniff(true);
    concrete_mw->update_options(updated_opts);

    const auto &retrieved_opts2 = concrete_mw->get_options();
    EXPECT_FALSE(retrieved_opts2.get_hsts_value().has_value()); // HSTS not in updated_opts
    EXPECT_TRUE(retrieved_opts2.get_set_x_content_type_options_nosniff());
}

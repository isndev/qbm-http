/**
 * @file qbm/http/tests/unit/middleware/middleware-csrf.cpp
 * @brief Unit tests for qb::http::CsrfMiddleware and qb::http::CsrfOptions (Huly QB-95).
 *
 * Drives the real qb::http::Router<Session> synchronously over the shared capturing
 * MockMiddlewareSession: a synthetic Request is routed, and the test asserts whether the handler ran, the
 * status and body of a refusal, and the token cookie a response carries.
 *
 * - Where a request comes from: safe methods, every `Sec-Fetch-Site` value, `Origin` against `Host`
 *   (HTTP/1.1 origin-form) and against the URI's authority (HTTP/2, HTTP/3, absolute-form), default and
 *   explicit ports, IPv6, case, `null`, a request with neither header.
 * - Trusted origins and exemptions, and the origins `trusted_origin()` refuses.
 * - The refusal: 403, `text/plain`, the verdict in the body, the chain stopped; `on_reject()`.
 * - Tokens (`QB_HAS_SSL`): the cookie and its attributes, the slot, no re-issue of a valid token, the
 *   header and the form field, a missing, different, forged or other-session token, a changed secret, a
 *   handler that rebuilds the response, the configuration refusals. Without SSL, `tokens()` refuses.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "../../shared/middleware_test_fixture.h"

#include <qbm/http/middleware/csrf.h>
#include <qbm/http/middleware/make.h>

using qb::http::CsrfOptions;
using qb::http::CsrfVerdict;
using qb::http::test::MockMiddlewareSession;

namespace middleware_csrf_test {

using Header = std::pair<std::string, std::string>;

class CsrfMiddlewareTest : public qb::http::test::MiddlewareTestFixture<MockMiddlewareSession> {
protected:
    /// A request to @p target (a path: HTTP/1.1 origin-form, Host example.test unless @p headers name one;
    /// an absolute URI: the authority HTTP/2 and HTTP/3 carry in the URI).
    static qb::http::Request
    request(qb::http::method method, std::vector<Header> const &headers = {}, std::string const &target = "/mw_test") {
        qb::http::Request req;
        req.method()      = method;
        req.uri()         = qb::io::uri(target);
        req.major_version = 1;
        req.minor_version = 1;
        bool host         = false;
        for (auto const &[name, value] : headers) {
            req.add_header(name, value);
            host = host || name == "Host";
        }
        if (!host && target.front() == '/')
            req.add_header("Host", "example.test");
        req.parse_cookie_header();
        return req;
    }

    static qb::http::Request
    post(std::vector<Header> const &headers = {}, std::string const &target = "/mw_test") {
        return request(qb::http::method::POST, headers, target);
    }

    void
    run(std::shared_ptr<qb::http::IMiddleware<MockMiddlewareSession>> middleware, qb::http::Request req) {
        configure_router_and_run(std::move(middleware), std::move(req));
    }

    void
    run(CsrfOptions options, qb::http::Request req) {
        run(qb::http::csrf_middleware<MockMiddlewareSession>(std::move(options)), std::move(req));
    }

    void
    expect_served() {
        EXPECT_TRUE(_session->_final_handler_called);
        EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    }

    void
    expect_refused(CsrfVerdict const verdict) {
        EXPECT_FALSE(_session->_final_handler_called);
        EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
        EXPECT_EQ(_session->_response.header("Content-Type"), "text/plain; charset=utf-8");
        EXPECT_EQ(_session->_response.body().template as<std::string>(), "Forbidden: " + std::string(qb::http::to_string(verdict)));
    }

    /// The Set-Cookie line for @p name in the last response, empty when there is none.
    std::string
    set_cookie(std::string const &name = "__Host-csrf") const {
        for (std::size_t i = 0; _session->_response.has_header("Set-Cookie") && i < 16; ++i) {
            std::string const &line = _session->_response.header("Set-Cookie", i);
            if (line.empty())
                break;
            if (line.rfind(name + "=", 0) == 0)
                return line;
        }
        return {};
    }

    /// The value of the token cookie the last response set, empty when it set none.
    std::string
    issued_token(std::string const &name = "__Host-csrf") const {
        std::string const line = set_cookie(name);
        if (line.empty())
            return {};
        auto const begin = name.size() + 1;
        return line.substr(begin, line.find(';', begin) - begin);
    }
};

// --- Where the request comes from -----------------------------------------------------------------------

TEST_F(CsrfMiddlewareTest, SafeMethodsPassFromAnywhere) {
    for (auto method : {qb::http::method::GET, qb::http::method::HEAD, qb::http::method::OPTIONS}) {
        _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
        _router->use(qb::http::csrf_middleware<MockMiddlewareSession>());
        _router->get("/mw_test", basic_handler());
        _router->add_route("/mw_test", qb::http::method::HEAD, basic_handler());
        _router->add_route("/mw_test", qb::http::method::OPTIONS, basic_handler());
        _router->compile();
        _session->reset();
        _router->route(_session, request(method, {{"Sec-Fetch-Site", "cross-site"}, {"Origin", "https://evil.test"}}));
        EXPECT_TRUE(_session->_final_handler_called) << std::to_string(method);
        EXPECT_NE(_session->_response.status(), qb::http::status::FORBIDDEN) << std::to_string(method);
    }
}

TEST_F(CsrfMiddlewareTest, FetchMetadataSameOriginAndNoneArePassed) {
    run(CsrfOptions{}, post({{"Sec-Fetch-Site", "same-origin"}, {"Origin", "https://example.test"}}));
    expect_served();
    run(CsrfOptions{}, post({{"Sec-Fetch-Site", "none"}}));
    expect_served();
}

TEST_F(CsrfMiddlewareTest, FetchMetadataCrossSiteSameSiteAndUnknownAreRefused) {
    for (char const *site : {"cross-site", "same-site", "something-new"}) {
        // Fetch Metadata wins over an Origin that would match: a browser that sends it says where the request comes from.
        run(CsrfOptions{}, post({{"Sec-Fetch-Site", site}, {"Origin", "http://example.test"}}));
        expect_refused(CsrfVerdict::cross_site);
    }
}

TEST_F(CsrfMiddlewareTest, OriginMatchingTheHostIsPassed) {
    run(CsrfOptions{}, post({{"Origin", "https://example.test"}}));
    expect_served();
    run(CsrfOptions{}, post({{"Origin", "https://EXAMPLE.test"}})); // hosts compare case-insensitively
    expect_served();
    run(CsrfOptions{}, post({{"Origin", "https://example.test"}, {"Host", "example.test:443"}})); // the default port spelled out
    expect_served();
    run(CsrfOptions{}, post({{"Origin", "http://example.test:8080"}, {"Host", "example.test:8080"}}));
    expect_served();
    run(CsrfOptions{}, post({{"Origin", "http://[::1]:8080"}, {"Host", "[::1]:8080"}}));
    expect_served();
    // The authority does not say whether the request arrived over TLS: an http page of the same host passes.
    run(CsrfOptions{}, post({{"Origin", "http://example.test"}}));
    expect_served();
}

TEST_F(CsrfMiddlewareTest, OriginNotMatchingTheHostIsRefused) {
    for (char const *origin :
         {"https://evil.test", "https://example.test:8443", "https://sub.example.test", "null", "https://example.test/path", "example.test",
          "ftp://example.test"}) {
        run(CsrfOptions{}, post({{"Origin", origin}}));
        expect_refused(CsrfVerdict::origin_mismatch);
    }
    run(CsrfOptions{}, post({{"Origin", "https://example.test"}, {"Host", "example.test:8443"}}));
    expect_refused(CsrfVerdict::origin_mismatch);
}

TEST_F(CsrfMiddlewareTest, OriginIsComparedWithTheUriAuthorityOfHttp2AndHttp3) {
    // HTTP/2 and HTTP/3 rebuild the URI from :scheme and :authority, and send no Host.
    run(CsrfOptions{}, post({{"Origin", "https://example.test:8443"}}, "https://example.test:8443/mw_test"));
    expect_served();
    run(CsrfOptions{}, post({{"Origin", "https://evil.test"}}, "https://example.test/mw_test"));
    expect_refused(CsrfVerdict::origin_mismatch);
    // An absolute-form target's authority wins over Host (RFC 9112 §3.2.2).
    run(CsrfOptions{}, post({{"Origin", "https://evil.test"}, {"Host", "evil.test"}}, "https://example.test/mw_test"));
    expect_refused(CsrfVerdict::origin_mismatch);
}

TEST_F(CsrfMiddlewareTest, ARequestWithNeitherHeaderIsPassed) {
    run(CsrfOptions{}, post());
    expect_served();
}

TEST_F(CsrfMiddlewareTest, ARequestWithoutAnAuthorityIsRefusedWhenItNamesAnOrigin) {
    run(CsrfOptions{}, post({{"Origin", "https://example.test"}, {"Host", ""}}));
    expect_refused(CsrfVerdict::origin_mismatch);
}

// --- Trusted origins and exemptions -----------------------------------------------------------------------

TEST_F(CsrfMiddlewareTest, ATrustedOriginIsPassedWhateverFetchMetadataSays) {
    CsrfOptions options;
    options.trusted_origin("https://app.example.test").trusted_origin("http://localhost:5173");
    run(options, post({{"Sec-Fetch-Site", "cross-site"}, {"Origin", "https://APP.example.test"}}));
    expect_served();
    run(options, post({{"Origin", "http://localhost:5173"}}));
    expect_served();
    run(options, post({{"Origin", "https://app.example.test:8443"}}));
    expect_refused(CsrfVerdict::origin_mismatch);
    run(options, post({{"Sec-Fetch-Site", "cross-site"}, {"Origin", "https://evil.test"}}));
    expect_refused(CsrfVerdict::cross_site);
}

TEST_F(CsrfMiddlewareTest, TrustedOriginRefusesWhatIsNotAnOrigin) {
    for (char const *origin :
         {"", "null", "app.example.test", "https://", "https://app.example.test/", "https://app.example.test/path",
          "https://app.example.test?x=1", "https://app.example.test#f", "https://user@app.example.test", "ftp://app.example.test",
          "https://app.example.test:99999"}) {
        CsrfOptions options;
        EXPECT_THROW(options.trusted_origin(origin), std::invalid_argument) << origin;
    }
}

TEST_F(CsrfMiddlewareTest, AnExemptRequestIsPassed) {
    CsrfOptions options;
    options.exempt([](qb::http::Request const &r) { return r.uri().path() == "/mw_test" && r.has_header("X-Webhook-Signature"); });
    run(options, post({{"Sec-Fetch-Site", "cross-site"}, {"X-Webhook-Signature", "sig"}}));
    expect_served();
    run(options, post({{"Sec-Fetch-Site", "cross-site"}}));
    expect_refused(CsrfVerdict::cross_site);
    EXPECT_THROW(options.exempt(nullptr), std::invalid_argument);
}

// --- The refusal ------------------------------------------------------------------------------------------

TEST_F(CsrfMiddlewareTest, OnRejectWritesTheResponseAndTheChainStops) {
    auto        middleware = qb::http::csrf_middleware<MockMiddlewareSession>();
    CsrfVerdict seen       = CsrfVerdict::allowed;
    middleware->on_reject([&seen](qb::http::Context<MockMiddlewareSession> &ctx, CsrfVerdict verdict) {
        seen                    = verdict;
        ctx.response().status() = qb::http::status::BAD_REQUEST;
        ctx.response().body()   = R"({"error":"csrf"})";
        ctx.response().set_header("Content-Type", "application/json");
    });
    run(middleware, post({{"Origin", "https://evil.test"}}));
    EXPECT_EQ(seen, CsrfVerdict::origin_mismatch);
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(_session->_response.body().template as<std::string>(), R"({"error":"csrf"})");
}

TEST_F(CsrfMiddlewareTest, TheVerdictsAreNamed) {
    EXPECT_EQ(qb::http::to_string(CsrfVerdict::allowed), "allowed");
    EXPECT_EQ(qb::http::to_string(CsrfVerdict::cross_site), "cross-site request");
    EXPECT_EQ(qb::http::to_string(CsrfVerdict::origin_mismatch), "origin mismatch");
    EXPECT_EQ(qb::http::to_string(CsrfVerdict::token_missing), "CSRF token missing");
    EXPECT_EQ(qb::http::to_string(CsrfVerdict::token_invalid), "CSRF token invalid");
}

TEST_F(CsrfMiddlewareTest, TheFactoryTagBuildsIt) {
    run(qb::http::middleware::make<qb::http::middleware::tags::csrf, MockMiddlewareSession>(), post({{"Origin", "https://evil.test"}}));
    expect_refused(CsrfVerdict::origin_mismatch);
    EXPECT_FALSE(qb::http::csrf_middleware<MockMiddlewareSession>()->options().tokens_enabled());
}

TEST_F(CsrfMiddlewareTest, CookieConfigurationRefusals) {
    CsrfOptions options;
    EXPECT_THROW(options.cookie_secure(false), std::invalid_argument); // __Host-csrf must be Secure
    EXPECT_THROW(options.cookie_name("bad name"), std::invalid_argument);
    EXPECT_THROW(options.cookie_name("bad;name"), std::invalid_argument);
    EXPECT_THROW(options.cookie_name(""), std::invalid_argument);
    EXPECT_THROW(options.header_name(""), std::invalid_argument);
    EXPECT_NO_THROW(options.cookie_name("csrf").cookie_secure(false));
    EXPECT_THROW(options.cookie_name("__secure-csrf"), std::invalid_argument); // the prefixes are case-insensitive
    EXPECT_THROW(options.cookie_name("__HOST-csrf"), std::invalid_argument);
    EXPECT_THROW(options.cookie_same_site(qb::http::SameSite::None), std::invalid_argument); // not Secure here
    CsrfOptions secure;
    EXPECT_NO_THROW(secure.cookie_same_site(qb::http::SameSite::None));
    EXPECT_THROW(secure.cookie_name("csrf").cookie_secure(false), std::invalid_argument); // SameSite=None needs Secure
}

#ifdef QB_HAS_SSL

// --- Tokens -----------------------------------------------------------------------------------------------

constexpr char const *secret       = "0123456789abcdef0123456789abcdef";
constexpr char const *other_secret = "fedcba9876543210fedcba9876543210";

TEST_F(CsrfMiddlewareTest, TokensRefuseAShortSecret) {
    CsrfOptions options;
    EXPECT_THROW(options.tokens("too short"), std::invalid_argument);
    EXPECT_THROW(options.tokens(std::string(CsrfOptions::min_secret_size - 1, 'x')), std::invalid_argument);
    EXPECT_NO_THROW(options.tokens(std::string(CsrfOptions::min_secret_size, 'x')));
    EXPECT_TRUE(options.tokens_enabled());
    EXPECT_THROW((void) CsrfOptions{}.issue_token(qb::http::Request{}), std::logic_error);
}

TEST_F(CsrfMiddlewareTest, AResponseWithoutAValidCookieCarriesAFreshTokenAndTheSlotHoldsIt) {
    CsrfOptions options;
    options.tokens(secret);
    std::string slot;
    _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
    _router->use(qb::http::csrf_middleware<MockMiddlewareSession>(options));
    _router->get("/mw_test", [&slot](auto ctx) {
        if (auto const *token = ctx->get_if(qb::http::csrf_token_slot))
            slot = *token;
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();
    _session->reset();
    _router->route(_session, request(qb::http::method::GET));

    std::string const line  = set_cookie();
    std::string const token = issued_token();
    ASSERT_FALSE(token.empty()) << line;
    EXPECT_EQ(slot, token);
    EXPECT_NE(line.find("Path=/"), std::string::npos) << line;
    EXPECT_NE(line.find("Secure"), std::string::npos) << line;
    EXPECT_NE(line.find("SameSite=Lax"), std::string::npos) << line;
    EXPECT_EQ(line.find("HttpOnly"), std::string::npos) << line; // the page's scripts read it
    EXPECT_EQ(line.find("Domain"), std::string::npos) << line;
    EXPECT_TRUE(options.token_valid(token, qb::http::Request{}));

    // A request that carries it gets no new one, and the slot holds the one it carries.
    slot.clear();
    _session->reset();
    _router->route(_session, request(qb::http::method::GET, {{"Cookie", "__Host-csrf=" + token}}));
    EXPECT_TRUE(set_cookie().empty());
    EXPECT_EQ(slot, token);
}

TEST_F(CsrfMiddlewareTest, AnUnsafeRequestMustEchoTheCookieToken) {
    CsrfOptions options;
    options.tokens(secret);
    std::string const token  = options.issue_token(qb::http::Request{});
    std::string const cookie = "__Host-csrf=" + token;

    run(options, post({{"Origin", "https://example.test"}, {"Cookie", cookie}, {"X-CSRF-Token", token}}));
    expect_served();
    EXPECT_TRUE(set_cookie().empty());

    run(options, post({{"Cookie", cookie}}));
    expect_refused(CsrfVerdict::token_missing);
    EXPECT_TRUE(set_cookie().empty()); // the cookie is valid: nothing to re-issue

    run(options, post({{"X-CSRF-Token", token}}));
    expect_refused(CsrfVerdict::token_missing);
    EXPECT_FALSE(issued_token().empty()); // the refusal carries one, so the page can retry

    std::string const other = options.issue_token(qb::http::Request{});
    run(options, post({{"Cookie", cookie}, {"X-CSRF-Token", other}}));
    expect_refused(CsrfVerdict::token_invalid);
}

TEST_F(CsrfMiddlewareTest, AForgedOrForeignTokenIsRefusedAndReplaced) {
    CsrfOptions options;
    options.tokens(secret);
    std::string const token = options.issue_token(qb::http::Request{});
    // The same nonce, another signature: a cookie the attacker wrote and echoes.
    std::string forged = token;
    forged.back()      = forged.back() == 'A' ? 'B' : 'A';
    run(options, post({{"Cookie", "__Host-csrf=" + forged}, {"X-CSRF-Token", forged}}));
    expect_refused(CsrfVerdict::token_invalid);
    EXPECT_FALSE(issued_token().empty());
    EXPECT_NE(issued_token(), forged);

    // Signed with another secret: every token is invalidated when the secret changes.
    CsrfOptions rotated;
    rotated.tokens(other_secret);
    run(rotated, post({{"Cookie", "__Host-csrf=" + token}, {"X-CSRF-Token", token}}));
    expect_refused(CsrfVerdict::token_invalid);
}

TEST_F(CsrfMiddlewareTest, TokenValidRefusesMalformedTokens) {
    CsrfOptions options;
    options.tokens(secret);
    std::string const token = options.issue_token(qb::http::Request{});
    auto const        dot   = token.find('.');
    ASSERT_NE(dot, std::string::npos);
    qb::http::Request const any;
    EXPECT_TRUE(options.token_valid(token, any));
    EXPECT_FALSE(options.token_valid("", any));
    EXPECT_FALSE(options.token_valid(token.substr(0, dot), any));     // no signature
    EXPECT_FALSE(options.token_valid(token.substr(1), any));          // a shorter nonce
    EXPECT_FALSE(options.token_valid("!" + token.substr(1), any));    // not base64url
    EXPECT_FALSE(options.token_valid(token + "A", any));              // a longer signature
    EXPECT_FALSE(options.token_valid(token.substr(0, dot + 1), any)); // an empty signature
    EXPECT_FALSE(CsrfOptions{}.token_valid(token, any));              // tokens off
}

TEST_F(CsrfMiddlewareTest, TheFormFieldSubmitsTheTokenWhenTheHeaderIsAbsent) {
    CsrfOptions options;
    options.tokens(secret);
    std::string const token     = options.issue_token(qb::http::Request{});
    auto              form_post = [&](std::string const &body, std::string const &type) {
        auto req   = post({{"Cookie", "__Host-csrf=" + token}, {"Content-Type", type}});
        req.body() = body;
        return req;
    };
    run(options, form_post("amount=10&_csrf=" + token + "&to=bob", "application/x-www-form-urlencoded"));
    expect_served();
    run(options, form_post("_csrf=" + token, "application/x-www-form-urlencoded; charset=utf-8"));
    expect_served();
    run(options, form_post("_csrf=" + token, "text/plain")); // only a urlencoded body is read
    expect_refused(CsrfVerdict::token_missing);
    run(options, form_post("amount=10", "application/x-www-form-urlencoded"));
    expect_refused(CsrfVerdict::token_missing);

    CsrfOptions header_only = options;
    header_only.form_field("");
    run(header_only, form_post("_csrf=" + token, "application/x-www-form-urlencoded"));
    expect_refused(CsrfVerdict::token_missing);
}

TEST_F(CsrfMiddlewareTest, AMultipartFormSubmitsTheTokenInItsField) {
    // An HTML form with a file input posts multipart/form-data and cannot set a header.
    CsrfOptions options;
    options.tokens(secret);
    std::string const token          = options.issue_token(qb::http::Request{});
    auto              multipart_post = [&](std::string const &body) {
        auto req   = post({{"Cookie", "__Host-csrf=" + token}, {"Content-Type", "multipart/form-data; boundary=XyZ"}});
        req.body() = body;
        return req;
    };
    std::string const file_part = "--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n"
                                  "Content-Type: text/plain\r\n\r\nhello\r\n";
    run(options, multipart_post(file_part + "--XyZ\r\nContent-Disposition: form-data; name=\"_csrf\"\r\n\r\n" + token + "\r\n--XyZ--\r\n"));
    expect_served();
    run(options, multipart_post(file_part + "--XyZ--\r\n"));
    expect_refused(CsrfVerdict::token_missing);
    run(options, multipart_post("not a multipart body"));
    expect_refused(CsrfVerdict::token_missing);
}

TEST_F(CsrfMiddlewareTest, ATokenIsBoundToItsSession) {
    CsrfOptions options;
    options.tokens(secret).session_binding([](qb::http::Request const &r) { return r.cookie_value("sid"); });
    auto const alice = options.issue_token(request(qb::http::method::GET, {{"Cookie", "sid=alice"}}));

    run(options, post({{"Cookie", "sid=alice; __Host-csrf=" + alice}, {"X-CSRF-Token", alice}}));
    expect_served();
    // Alice's token planted in Mallory's session, or kept across a login: refused, and a new one issued for it.
    run(options, post({{"Cookie", "sid=mallory; __Host-csrf=" + alice}, {"X-CSRF-Token", alice}}));
    expect_refused(CsrfVerdict::token_invalid);
    EXPECT_TRUE(options.token_valid(issued_token(), request(qb::http::method::GET, {{"Cookie", "sid=mallory"}})));
    EXPECT_FALSE(options.token_valid(issued_token(), request(qb::http::method::GET, {{"Cookie", "sid=alice"}})));
}

TEST_F(CsrfMiddlewareTest, TheOriginLayerRunsBeforeTheToken) {
    CsrfOptions options;
    options.tokens(secret);
    std::string const token = options.issue_token(qb::http::Request{});
    run(options, post({{"Sec-Fetch-Site", "cross-site"}, {"Cookie", "__Host-csrf=" + token}, {"X-CSRF-Token", token}}));
    expect_refused(CsrfVerdict::cross_site);
    // A trusted origin and an exemption skip the token too.
    CsrfOptions trusting = options;
    trusting.trusted_origin("https://app.example.test").exempt([](qb::http::Request const &r) { return r.has_header("X-Webhook"); });
    run(trusting, post({{"Sec-Fetch-Site", "cross-site"}, {"Origin", "https://app.example.test"}}));
    expect_served();
    run(trusting, post({{"X-Webhook", "1"}}));
    expect_served();
}

TEST_F(CsrfMiddlewareTest, TheCookieSurvivesAHandlerThatRebuildsTheResponse) {
    CsrfOptions options;
    options.tokens(secret)
        .cookie_name("csrf")
        .cookie_secure(false)
        .cookie_same_site(qb::http::SameSite::Strict)
        .cookie_max_age(std::chrono::hours(2));
    _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
    _router->use(qb::http::csrf_middleware<MockMiddlewareSession>(options));
    _router->get("/mw_test", [](auto ctx) {
        ctx->response()          = qb::http::Response{};
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();
    _session->reset();
    _router->route(_session, request(qb::http::method::GET));
    std::string const line = set_cookie("csrf");
    ASSERT_FALSE(issued_token("csrf").empty()) << line;
    EXPECT_EQ(line.find("Secure"), std::string::npos) << line;
    EXPECT_NE(line.find("SameSite=Strict"), std::string::npos) << line;
    EXPECT_NE(line.find("Max-Age=7200"), std::string::npos) << line;
}

#else

TEST_F(CsrfMiddlewareTest, TokensNeedSsl) {
    CsrfOptions options;
    EXPECT_THROW(options.tokens("0123456789abcdef0123456789abcdef"), std::logic_error);
    EXPECT_FALSE(options.tokens_enabled());
}

#endif

} // namespace middleware_csrf_test

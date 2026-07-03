/**
 * @file qbm/http/tests/unit/middleware/middleware-cors.cpp
 * @brief Unit tests for qb::http::CorsMiddleware (origin matching, preflight, ReDoS limits).
 *
 * Drives the real Router<Session> synchronously over the shared
 * MiddlewareTestFixture. Origin-allow/deny, preflight (OPTIONS) negotiation,
 * credential reflection, Vary bookkeeping, and the documented security limits
 * (MAX_ORIGIN_LENGTH / MAX_REGEX_PATTERNS / MAX_REGEX_PATTERN_LENGTH) are all
 * pinned to exact values; the ReDoS test is adversarial (a catastrophic-
 * backtracking pattern fed an over-length input must fail-closed without a hang).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <algorithm>
#include <chrono>
#include <set>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "../http.h"
#include "../middleware/cors.h"

#include "../../shared/middleware_test_fixture.h"

namespace {

using qb::http::test::MiddlewareTestFixture;
using qb::http::test::MockMiddlewareSession;

/**
 * @brief CORS fixture: a request factory that sets the Origin header plus a
 *        terminal GET/OPTIONS handler, and structural header helpers.
 */
class CorsMiddlewareTest : public MiddlewareTestFixture<MockMiddlewareSession> {
protected:
    /** @brief Builds a request, optionally attaching an Origin header. */
    qb::http::Request
    cors_request(qb::http::method method_val, const std::string &origin_header, const std::string &path = "/cors_test") {
        auto req = create_request(method_val, path);
        if (!origin_header.empty()) {
            req.set_header("Origin", origin_header);
        }
        return req;
    }

    /**
     * @brief Wires the CORS middleware ahead of GET+OPTIONS handlers and routes once.
     *
     * Distinct from the base helper because CORS must own the OPTIONS route to
     * exercise the preflight short-circuit.
     */
    void
    run_cors(std::shared_ptr<qb::http::CorsMiddleware<MockMiddlewareSession>> cors_mw, qb::http::Request request,
             const std::string &path = "/cors_test") {
        _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
        _router->use(std::move(cors_mw));
        _router->get(path, basic_handler());
        _router->options(path, basic_handler());
        _router->compile();

        _session->reset();
        _router->route(_session, std::move(request));
    }

    /** @brief Mutable access to the captured response. */
    [[nodiscard]] qb::http::Response &
    response() {
        return _session->_response;
    }

    /** @brief Reads a single response header value as std::string. */
    [[nodiscard]] std::string
    header(const std::string &name) const {
        return std::string(_session->_response.header(name));
    }

    /** @brief True if the response 'Vary' header carries @p value as one of its tokens. */
    [[nodiscard]] bool
    has_vary_value(const std::string &value) const {
        const auto it = _session->_response.headers().find("Vary");
        if (it == _session->_response.headers().end()) {
            return false;
        }
        return std::find(it->second.begin(), it->second.end(), value) != it->second.end();
    }

    /** @brief Splits a comma-separated header value into a trimmed token set (order-independent). */
    [[nodiscard]] static std::set<std::string>
    token_set(const std::string &csv) {
        std::set<std::string> tokens;
        std::size_t           start = 0;
        while (start <= csv.size()) {
            std::size_t comma = csv.find(',', start);
            std::string tok   = csv.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
            // trim
            std::size_t b = tok.find_first_not_of(" \t");
            std::size_t e = tok.find_last_not_of(" \t");
            if (b != std::string::npos) {
                tokens.insert(tok.substr(b, e - b + 1));
            }
            if (comma == std::string::npos) {
                break;
            }
            start = comma + 1;
        }
        return tokens;
    }
};

// --- Origin matching ---------------------------------------------------------

TEST_F(CorsMiddlewareTest, AllowSpecificOrigin) {
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(qb::http::CorsOptions().origins({"http://example.com"}));
    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://example.com"));

    EXPECT_EQ(response().status(), qb::http::status::OK);
    EXPECT_EQ(header("Access-Control-Allow-Origin"), "http://example.com");
    EXPECT_TRUE(has_vary_value("Origin"));
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, OriginNotAllowed) {
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(qb::http::CorsOptions().origins({"http://example.com"}));
    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://other.com"));

    EXPECT_EQ(response().status(), qb::http::status::OK);
    EXPECT_TRUE(header("Access-Control-Allow-Origin").empty());
    EXPECT_TRUE(has_vary_value("Origin")); // Vary:Origin added even on deny (cache correctness).
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, AllowAnyOriginWildcard) {
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(qb::http::CorsOptions().origins({"*"}));
    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://random.org"));

    EXPECT_EQ(response().status(), qb::http::status::OK);
    EXPECT_EQ(header("Access-Control-Allow-Origin"), "*");
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, NoOriginHeader) {
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(qb::http::CorsOptions().origins({"http://example.com"}));
    run_cors(cors_mw, cors_request(qb::http::method::GET, ""));

    EXPECT_EQ(response().status(), qb::http::status::OK);
    EXPECT_TRUE(header("Access-Control-Allow-Origin").empty());
    EXPECT_FALSE(has_vary_value("Origin")); // No Origin in request ⇒ no Vary:Origin.
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, MultipleExactOrigins) {
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(qb::http::CorsOptions().origins({"http://site1.com", "https://site2.org"}));

    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://site1.com"));
    EXPECT_EQ(header("Access-Control-Allow-Origin"), "http://site1.com");
    EXPECT_TRUE(_session->_final_handler_called);

    run_cors(cors_mw, cors_request(qb::http::method::GET, "https://site2.org"));
    EXPECT_EQ(header("Access-Control-Allow-Origin"), "https://site2.org");

    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://othersite.net"));
    EXPECT_TRUE(header("Access-Control-Allow-Origin").empty());
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, RegexOriginMatching) {
    qb::http::CorsOptions options;
    options.origin_patterns({"http://.*\\.example\\.com", "http://example\\.com"});
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://sub.example.com"));
    EXPECT_EQ(header("Access-Control-Allow-Origin"), "http://sub.example.com");

    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://example.com"));
    EXPECT_EQ(header("Access-Control-Allow-Origin"), "http://example.com");

    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://another.domain.com"));
    EXPECT_TRUE(header("Access-Control-Allow-Origin").empty());

    run_cors(cors_mw, cors_request(qb::http::method::GET, "https://sub.example.com")); // scheme mismatch
    EXPECT_TRUE(header("Access-Control-Allow-Origin").empty());
}

TEST_F(CorsMiddlewareTest, FunctionOriginMatching) {
    qb::http::CorsOptions options;
    options.origin_matcher([](const std::string &origin) -> bool {
        return origin == "http://allowed.by.function.com" || origin == "https://another.functional.match";
    });
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://allowed.by.function.com"));
    EXPECT_EQ(header("Access-Control-Allow-Origin"), "http://allowed.by.function.com");

    run_cors(cors_mw, cors_request(qb::http::method::GET, "https://another.functional.match"));
    EXPECT_EQ(header("Access-Control-Allow-Origin"), "https://another.functional.match");

    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://denied.by.function.com"));
    EXPECT_TRUE(header("Access-Control-Allow-Origin").empty());
}

TEST_F(CorsMiddlewareTest, ThrowingFunctionMatcherFailsClosedAndRequestContinues) {
    qb::http::CorsOptions options;
    options.origin_matcher([](const std::string &) -> bool { throw std::runtime_error("matcher failure"); });
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://example.com"));

    EXPECT_EQ(response().status(), qb::http::status::OK);
    EXPECT_TRUE(header("Access-Control-Allow-Origin").empty()); // fail-closed: no CORS grant.
    EXPECT_TRUE(_session->_final_handler_called);
}

// Direct CorsOptions / regex_match_with_timeout guards that the middleware path
// pre-filters (it rejects empty and over-length origins before these inner
// checks), so they are only reachable by calling the API directly.
TEST(CorsOptionsDirect, EmptyOriginIsNotAllowed) {
    qb::http::CorsOptions o;
    o.origins({"http://a.com"});
    EXPECT_FALSE(o.is_origin_allowed("")); // empty-origin guard
}

TEST(CorsOptionsDirect, FunctionStrategyWithNullMatcherIsFalse) {
    qb::http::CorsOptions o;
    o.origin_matcher(std::function<bool(const std::string &)>{}); // empty std::function
    EXPECT_FALSE(o.is_origin_allowed("http://a.com"));            // null-matcher guard
}

TEST(CorsOptionsDirect, InvalidRegexPatternIsSkippedAtCompile) {
    qb::http::CorsOptions o;
    o.origin_patterns({"["});                          // unbalanced -> regex_error caught
    EXPECT_FALSE(o.is_origin_allowed("http://a.com")); // compile-time skip, no match
}

TEST(CorsRegexMatcher, OverlongOriginShortCircuitsToFalse) {
    std::regex  re("http://.*");
    std::string evil(qb::http::cors_security_limits::MAX_ORIGIN_LENGTH + 1, 'a');
    EXPECT_FALSE(qb::http::regex_match_with_timeout(evil, re)); // length short-circuit
}

// --- Credentials -------------------------------------------------------------

TEST_F(CorsMiddlewareTest, CredentialsAllowed) {
    qb::http::CorsOptions options;
    options.origins({"http://creds.example.com"}).credentials(qb::http::CorsOptions::AllowCredentials::Yes);
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://creds.example.com"));

    EXPECT_EQ(header("Access-Control-Allow-Origin"), "http://creds.example.com");
    EXPECT_EQ(header("Access-Control-Allow-Credentials"), "true");
}

TEST_F(CorsMiddlewareTest, WildcardOriginWithCredentialsReflectsSpecificOrigin) {
    qb::http::CorsOptions options;
    options.origins({"*"}).credentials(qb::http::CorsOptions::AllowCredentials::Yes);
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://specific.example.com"));

    // Per spec, '*' must be replaced by the concrete origin when credentials are allowed.
    EXPECT_EQ(header("Access-Control-Allow-Origin"), "http://specific.example.com");
    EXPECT_EQ(header("Access-Control-Allow-Credentials"), "true");
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, DefaultPermissiveDoesNotReflectOriginOrSendCredentials) {
    // The DEFAULT middleware (permissive) must be safe: allow any origin via a LITERAL '*'
    // and send NO Access-Control-Allow-Credentials. The old default paired origins({"*"})
    // with credentials(Yes), which made process() reflect the caller's Origin and add
    // Allow-Credentials:true — letting any site read a logged-in victim's authenticated
    // responses. cors_middleware() with no options uses CorsOptions::permissive().
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(); // default == permissive()

    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://evil.example.com"));

    EXPECT_EQ(header("Access-Control-Allow-Origin"), "*");           // literal wildcard, NOT the reflected origin
    EXPECT_TRUE(header("Access-Control-Allow-Credentials").empty()); // credentials never sent with '*'
}

TEST_F(CorsMiddlewareTest, ActualRequestExposesHeaders) {
    qb::http::CorsOptions options;
    options.origins({"http://example.com"}).expose_headers({"X-My-Custom-Header", "Content-Length"});
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://example.com"));

    EXPECT_EQ(header("Access-Control-Allow-Origin"), "http://example.com");
    EXPECT_EQ(token_set(header("Access-Control-Expose-Headers")), (std::set<std::string>{"X-My-Custom-Header", "Content-Length"}));
    EXPECT_TRUE(_session->_final_handler_called);
}

// --- Preflight ---------------------------------------------------------------

TEST_F(CorsMiddlewareTest, PreflightRequest) {
    qb::http::CorsOptions options;
    options.origins({"http://localhost:3000"})
        .methods({"GET", "POST", "OPTIONS"})
        .headers({"Content-Type", "Authorization"})
        .max_age(std::chrono::seconds(3600));
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    auto req = cors_request(qb::http::method::OPTIONS, "http://localhost:3000");
    req.set_header("Access-Control-Request-Method", "POST");
    req.set_header("Access-Control-Request-Headers", "Content-Type, Authorization");
    run_cors(cors_mw, std::move(req));

    EXPECT_EQ(response().status(), qb::http::status::NO_CONTENT);
    EXPECT_EQ(header("Access-Control-Allow-Origin"), "http://localhost:3000");
    EXPECT_EQ(token_set(header("Access-Control-Allow-Methods")), (std::set<std::string>{"GET", "POST", "OPTIONS"}));
    EXPECT_EQ(token_set(header("Access-Control-Allow-Headers")), (std::set<std::string>{"Content-Type", "Authorization"}));
    EXPECT_EQ(header("Access-Control-Max-Age"), "3600");
    EXPECT_TRUE(has_vary_value("Origin"));
    EXPECT_TRUE(has_vary_value("Access-Control-Request-Method"));
    EXPECT_TRUE(has_vary_value("Access-Control-Request-Headers"));
    EXPECT_FALSE(_session->_final_handler_called); // CORS short-circuits preflight.
}

TEST_F(CorsMiddlewareTest, PreflightRejectsMethodNotAllowed) {
    qb::http::CorsOptions options;
    options.origins({"http://localhost:3000"}).methods({"GET", "POST", "OPTIONS"}).headers({"Content-Type"});
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    auto req = cors_request(qb::http::method::OPTIONS, "http://localhost:3000");
    req.set_header("Access-Control-Request-Method", "DELETE");
    run_cors(cors_mw, std::move(req));

    EXPECT_EQ(response().status(), qb::http::status::FORBIDDEN);
    EXPECT_TRUE(header("Access-Control-Allow-Methods").empty());
    EXPECT_TRUE(has_vary_value("Origin"));
    EXPECT_TRUE(has_vary_value("Access-Control-Request-Method"));
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, PreflightEmptyMethodAllowListFailsClosed) {
    qb::http::CorsOptions options;
    options.origins({"http://localhost:3000"}).methods({});
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    auto req = cors_request(qb::http::method::OPTIONS, "http://localhost:3000");
    req.set_header("Access-Control-Request-Method", "POST");
    run_cors(cors_mw, std::move(req));

    EXPECT_EQ(response().status(), qb::http::status::FORBIDDEN);
    EXPECT_TRUE(header("Access-Control-Allow-Methods").empty());
    EXPECT_TRUE(has_vary_value("Access-Control-Request-Method"));
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, PreflightEchoesSubsetOfRequestedHeaders) {
    qb::http::CorsOptions options;
    options.origins({"http://example.com"})
        .methods({"GET", "POST", "OPTIONS"})
        .headers({"Content-Type", "Authorization", "X-Custom-Header", "X-Another-Header"})
        .max_age(std::chrono::seconds(3600));
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    // Scenario 1: client asks for a strict subset → only that subset is echoed.
    auto req1 = cors_request(qb::http::method::OPTIONS, "http://example.com");
    req1.set_header("Access-Control-Request-Method", "POST");
    req1.set_header("Access-Control-Request-Headers", "Content-Type, X-Custom-Header");
    run_cors(cors_mw, std::move(req1));

    EXPECT_EQ(response().status(), qb::http::status::NO_CONTENT);
    EXPECT_EQ(token_set(header("Access-Control-Allow-Headers")), (std::set<std::string>{"Content-Type", "X-Custom-Header"}));
    EXPECT_EQ(header("Access-Control-Max-Age"), "3600");
    EXPECT_FALSE(_session->_final_handler_called);

    // Scenario 2: client omits A-C-Request-Headers → server advertises its full allow-list.
    auto req2 = cors_request(qb::http::method::OPTIONS, "http://example.com");
    req2.set_header("Access-Control-Request-Method", "GET");
    run_cors(cors_mw, std::move(req2));
    EXPECT_EQ(response().status(), qb::http::status::NO_CONTENT);
    EXPECT_EQ(token_set(header("Access-Control-Allow-Headers")),
              (std::set<std::string>{"Content-Type", "Authorization", "X-Custom-Header", "X-Another-Header"}));
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, PreflightServerHasNoAllowedHeadersDropsClientRequested) {
    qb::http::CorsOptions options;
    options.origins({"http://example.com"}).methods({"GET", "POST", "OPTIONS"}).max_age(std::chrono::seconds(3600));
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    auto req = cors_request(qb::http::method::OPTIONS, "http://example.com");
    req.set_header("Access-Control-Request-Method", "POST");
    req.set_header("Access-Control-Request-Headers", "X-Should-Not-Be-Allowed");
    run_cors(cors_mw, std::move(req));

    EXPECT_EQ(response().status(), qb::http::status::NO_CONTENT);
    EXPECT_EQ(header("Access-Control-Allow-Headers"), "") << "Unconfigured headers must not be echoed.";
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, PreflightServerNoHeadersClientNoHeaders) {
    qb::http::CorsOptions options;
    options.origins({"http://example.com"}).methods({"GET", "POST"});
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    auto req = cors_request(qb::http::method::OPTIONS, "http://example.com");
    req.set_header("Access-Control-Request-Method", "POST");
    run_cors(cors_mw, std::move(req));

    EXPECT_EQ(response().status(), qb::http::status::NO_CONTENT);
    EXPECT_EQ(token_set(header("Access-Control-Allow-Methods")), (std::set<std::string>{"GET", "POST"}));
    EXPECT_TRUE(header("Access-Control-Allow-Headers").empty());
    EXPECT_TRUE(has_vary_value("Origin"));
    // No client A-C-Request-Headers and no server allow-list ⇒ no Vary:A-C-R-H.
    EXPECT_FALSE(has_vary_value("Access-Control-Request-Headers"));
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, PreflightCaseInsensitiveRequestHeaders) {
    qb::http::CorsOptions options;
    options.origins({"http://example.com"}).methods({"PUT"}).headers({"CoNtEnT-TyPe", "X-API-KEY", "Authorization"});
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    auto req = cors_request(qb::http::method::OPTIONS, "http://example.com");
    req.set_header("Access-Control-Request-Method", "PUT");
    req.set_header("Access-Control-Request-Headers", "content-type, x-api-key, X-Non-Allowed-Header");
    run_cors(cors_mw, std::move(req));

    EXPECT_EQ(response().status(), qb::http::status::NO_CONTENT);
    // The middleware echoes the client's spelling for the headers that matched case-insensitively.
    EXPECT_EQ(token_set(header("Access-Control-Allow-Headers")), (std::set<std::string>{"content-type", "x-api-key"}));
    EXPECT_FALSE(_session->_final_handler_called);
}

// --- Factory presets ---------------------------------------------------------

TEST_F(CorsMiddlewareTest, FactoryFunctions) {
    auto dev_mw = qb::http::CorsMiddleware<MockMiddlewareSession>::dev();
    EXPECT_EQ(dev_mw->name(), "DevCorsMiddleware");
    EXPECT_TRUE(dev_mw->get_cors_options().is_origin_allowed("http://any.origin.com"));

    auto secure_mw = qb::http::CorsMiddleware<MockMiddlewareSession>::secure({"https://secure.com"});
    EXPECT_EQ(secure_mw->name(), "SecureCorsMiddleware");
    EXPECT_TRUE(secure_mw->get_cors_options().is_origin_allowed("https://secure.com"));
    EXPECT_FALSE(secure_mw->get_cors_options().is_origin_allowed("http://notsecure.com"));
}

// ====================================================================
// Security limits (cors_security_limits)
// ====================================================================

TEST_F(CorsMiddlewareTest, CorsSecurityLimitsConstants) {
    EXPECT_EQ(qb::http::cors_security_limits::MAX_ORIGIN_LENGTH, 2048u);
    EXPECT_EQ(qb::http::cors_security_limits::MAX_REGEX_PATTERNS, 100u);
    EXPECT_EQ(qb::http::cors_security_limits::MAX_REGEX_PATTERN_LENGTH, 1024u);
    EXPECT_EQ(qb::http::cors_security_limits::MAX_REGEX_EXECUTION_TIME, std::chrono::milliseconds(100));
}

TEST_F(CorsMiddlewareTest, MaxOriginLengthBoundary) {
    // Exact-match strategy bounds the Origin at MAX_ORIGIN_LENGTH (2048) inclusive.
    qb::http::CorsOptions options;
    // Allow both the at-limit and just-over-limit candidates by exact value so that
    // ONLY the length guard (not origin mismatch) decides the outcome.
    const std::string prefix = "http://";
    std::string       at_limit(qb::http::cors_security_limits::MAX_ORIGIN_LENGTH - prefix.size(), 'x');
    at_limit               = prefix + at_limit; // length == 2048
    std::string over_limit = at_limit + "y";    // length == 2049
    ASSERT_EQ(at_limit.size(), 2048u);
    ASSERT_EQ(over_limit.size(), 2049u);

    options.origins({at_limit, over_limit});
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    // 2048 → accepted, origin reflected.
    run_cors(cors_mw, cors_request(qb::http::method::GET, at_limit));
    EXPECT_EQ(response().status(), qb::http::status::OK);
    EXPECT_EQ(header("Access-Control-Allow-Origin"), at_limit);
    EXPECT_TRUE(_session->_final_handler_called);

    // 2049 → rejected by the length guard even though it is in the allow-list.
    run_cors(cors_mw, cors_request(qb::http::method::GET, over_limit));
    EXPECT_EQ(response().status(), qb::http::status::OK);
    EXPECT_TRUE(header("Access-Control-Allow-Origin").empty());
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, OverlongOriginRejectedEvenWithWildcardAndCredentials) {
    qb::http::CorsOptions options;
    options.origins({"*"}).credentials(qb::http::CorsOptions::AllowCredentials::Yes);
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    std::string long_origin = "http://";
    long_origin.append(qb::http::cors_security_limits::MAX_ORIGIN_LENGTH + 128, 'b');

    run_cors(cors_mw, cors_request(qb::http::method::GET, long_origin));

    EXPECT_EQ(response().status(), qb::http::status::OK);
    EXPECT_TRUE(header("Access-Control-Allow-Origin").empty());
    EXPECT_TRUE(header("Access-Control-Allow-Credentials").empty());
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, ReDoSProtectionRegexTimeout) {
    // Adversarial: a catastrophic-backtracking pattern ((a+)+$) fed an over-length,
    // non-matching input. With std::regex this is the classic exponential-blowup
    // case; the MAX_ORIGIN_LENGTH guard must short-circuit (return false) BEFORE
    // std::regex_match is ever invoked, so the call returns promptly and fail-closed.
    qb::http::CorsOptions options;
    options.origin_patterns({"^(a+)+$"});
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    std::string evil = std::string(qb::http::cors_security_limits::MAX_ORIGIN_LENGTH + 1, 'a');
    evil += "!"; // ensure it cannot match, forcing maximal backtracking if it ran.
    ASSERT_GT(evil.size(), qb::http::cors_security_limits::MAX_ORIGIN_LENGTH);

    const auto start = std::chrono::steady_clock::now();
    run_cors(cors_mw, cors_request(qb::http::method::GET, evil));
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(response().status(), qb::http::status::OK);
    EXPECT_TRUE(header("Access-Control-Allow-Origin").empty()); // fail-closed.
    EXPECT_TRUE(_session->_final_handler_called);
    // The over-length guard must make this near-instant; a real ReDoS would take seconds.
    EXPECT_LT(elapsed, std::chrono::seconds(1)) << "Over-length guard did not short-circuit the regex.";
}

TEST_F(CorsMiddlewareTest, RegexStrategyRejectsOverlongOriginInput) {
    qb::http::CorsOptions options;
    options.origin_patterns({"http://.*"});
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    std::string long_origin = "http://";
    long_origin.append(qb::http::cors_security_limits::MAX_ORIGIN_LENGTH + 64, 'a');

    run_cors(cors_mw, cors_request(qb::http::method::GET, long_origin));

    EXPECT_EQ(response().status(), qb::http::status::OK);
    EXPECT_TRUE(header("Access-Control-Allow-Origin").empty());
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, MaxRegexPatternsCapEnforced) {
    // More than MAX_REGEX_PATTERNS patterns are configured; only the first
    // MAX_REGEX_PATTERNS are compiled. A pattern at index >= the cap must NOT match.
    constexpr std::size_t cap = qb::http::cors_security_limits::MAX_REGEX_PATTERNS;

    std::vector<std::string> patterns;
    patterns.reserve(cap + 5);
    // The first `cap` patterns are deliberately non-matching literals.
    for (std::size_t i = 0; i < cap; ++i) {
        patterns.push_back("http://never-match-" + std::to_string(i) + "\\.example");
    }
    // This pattern (index == cap) would match our test origin IF it were compiled,
    // but it sits beyond the cap and so must be ignored.
    patterns.push_back("http://beyond\\.cap\\.example");

    qb::http::CorsOptions options;
    options.origin_patterns(patterns);
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    run_cors(cors_mw, cors_request(qb::http::method::GET, "http://beyond.cap.example"));

    EXPECT_EQ(response().status(), qb::http::status::OK);
    EXPECT_TRUE(header("Access-Control-Allow-Origin").empty()) << "Pattern beyond MAX_REGEX_PATTERNS should not have been compiled/matched.";
    EXPECT_TRUE(_session->_final_handler_called);

    // Sanity: a matching pattern within the cap DOES match.
    std::vector<std::string> within = patterns;
    within[0]                       = "http://within\\.cap\\.example";
    qb::http::CorsOptions options2;
    options2.origin_patterns(within);
    auto cors_mw2 = qb::http::cors_middleware<MockMiddlewareSession>(options2);
    run_cors(cors_mw2, cors_request(qb::http::method::GET, "http://within.cap.example"));
    EXPECT_EQ(header("Access-Control-Allow-Origin"), "http://within.cap.example");
}

TEST_F(CorsMiddlewareTest, MaxRegexPatternLengthSkipsOverlongPattern) {
    // A pattern longer than MAX_REGEX_PATTERN_LENGTH is skipped at compile time,
    // so an origin that would have matched it is NOT allowed.
    std::string overlong = "http://";
    overlong.append(qb::http::cors_security_limits::MAX_REGEX_PATTERN_LENGTH + 8, 'a');
    overlong += ".*";

    qb::http::CorsOptions options;
    options.origin_patterns({overlong});
    auto cors_mw = qb::http::cors_middleware<MockMiddlewareSession>(options);

    std::string origin = "http://";
    origin.append(qb::http::cors_security_limits::MAX_REGEX_PATTERN_LENGTH + 8, 'a');
    origin += "zzz"; // would match overlong if it had been compiled.

    run_cors(cors_mw, cors_request(qb::http::method::GET, origin));

    EXPECT_EQ(response().status(), qb::http::status::OK);
    EXPECT_TRUE(header("Access-Control-Allow-Origin").empty());
    EXPECT_TRUE(_session->_final_handler_called);
}

} // namespace

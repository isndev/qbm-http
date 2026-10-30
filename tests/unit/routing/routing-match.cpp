/**
 * @file qbm/http/tests/unit/routing/routing-match.cpp
 * @brief Broad-suite routing match behaviour: static / param / wildcard matching,
 *        precedence, trailing-slash equivalence, case sensitivity, and 404.
 *
 * One of the four focused unit files carved out of the legacy `test-router.cpp`
 * monolith. This file owns the *broad, end-to-end-shaped* match cases that drive a
 * request through a compiled @ref qb::http::Router and assert the observable
 * @ref qb::http::Response (status + body). The exhaustive radix-matcher primitive
 * spec (per-segment edge cases, %2F decode, identical-structure-different-method,
 * etc.) lives in its sibling `router-match.cpp`; here we keep the higher-level
 * "real route table" scenarios so the two do not duplicate primitives.
 *
 * Adopts the shared @ref qb::http::test::MockSession / @ref create_request from
 * `shared/mock_session.h` (the file no longer carries its own inline session copy).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "../../shared/mock_session.h"
#include <qb/io/uri.h>
#include <qbm/http/http.h>

using qb::http::test::create_request;
using qb::http::test::MockSession;

namespace {

/**
 * @brief Fixture: a fresh, default-constructed Router + a capturing MockSession per test.
 */
class RoutingMatchTest : public ::testing::Test {
protected:
    std::shared_ptr<MockSession>  session;
    qb::http::Router<MockSession> router;

    void
    SetUp() override {
        session = std::make_shared<MockSession>();
        router  = qb::http::Router<MockSession>();
    }

    /** @brief Compile, route a single GET, and return the captured response. */
    qb::http::Response &
    route_get(const std::string &path) {
        router.compile();
        router.route(session, create_request(qb::http::method::GET, path));
        return session->_response;
    }
};

// --------------------------------------------------------------------------
// Static matching
// --------------------------------------------------------------------------

TEST_F(RoutingMatchTest, StaticRouteMatchesAndRunsHandler) {
    router.get("/hello", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "world";
        ctx->complete();
    });

    auto &resp = route_get("/hello");

    EXPECT_EQ(resp.status(), qb::http::status::OK);
    EXPECT_EQ(resp.body().template as<std::string>(), "world");
    EXPECT_EQ(session->response_write_count(), 1u);
}

TEST_F(RoutingMatchTest, RootPathMatches) {
    router.get("/", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "root";
        ctx->complete();
    });

    auto &resp = route_get("/");

    EXPECT_EQ(resp.status(), qb::http::status::OK);
    EXPECT_EQ(resp.body().template as<std::string>(), "root");
    EXPECT_EQ(session->response_write_count(), 1u);
}

TEST_F(RoutingMatchTest, UnmatchedPathYields404) {
    router.get("/known", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });

    auto &resp = route_get("/unknown");

    EXPECT_EQ(resp.status(), qb::http::status::NOT_FOUND);
    EXPECT_EQ(session->response_write_count(), 1u);
}

TEST_F(RoutingMatchTest, TrailingSlashIsEquivalent) {
    router.get("/path", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "matched";
        ctx->complete();
    });
    router.compile();

    // With trailing slash.
    router.route(session, create_request(qb::http::method::GET, "/path/"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "matched");
    EXPECT_EQ(session->response_write_count(), 1u);

    session->reset();

    // Without trailing slash.
    router.route(session, create_request(qb::http::method::GET, "/path"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "matched");
    EXPECT_EQ(session->response_write_count(), 1u);
}

TEST_F(RoutingMatchTest, PathMatchingIsCaseSensitive) {
    router.get("/casepath", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "correct";
        ctx->complete();
    });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/casepath"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "correct");

    session->reset();

    // Mismatched case must 404 (radix tree is byte-exact, not case-folded).
    router.route(session, create_request(qb::http::method::GET, "/CasePath"));
    EXPECT_EQ(session->_response.status(), qb::http::status::NOT_FOUND);
    EXPECT_EQ(session->response_write_count(), 1u);
}

// --------------------------------------------------------------------------
// Parameter matching
// --------------------------------------------------------------------------

TEST_F(RoutingMatchTest, SingleParameterIsCaptured) {
    router.get("/users/:id/profile", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "User ID: " + ctx->path_param("id");
        ctx->complete();
    });

    auto &resp = route_get("/users/123/profile");

    EXPECT_EQ(resp.status(), qb::http::status::OK);
    EXPECT_EQ(resp.body().template as<std::string>(), "User ID: 123");
    EXPECT_EQ(session->response_write_count(), 1u);
}

TEST_F(RoutingMatchTest, MultipleParametersAreCaptured) {
    router.get("/users/:userId/items/:itemId", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "User: " + ctx->path_param("userId") + ", Item: " + ctx->path_param("itemId");
        ctx->complete();
    });

    auto &resp = route_get("/users/u42/items/i99");

    EXPECT_EQ(resp.status(), qb::http::status::OK);
    EXPECT_EQ(resp.body().template as<std::string>(), "User: u42, Item: i99");
}

TEST_F(RoutingMatchTest, ParameterAtEndOfPathIsCaptured) {
    router.get("/content/:pageId", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "Page: " + ctx->path_param("pageId");
        ctx->complete();
    });

    auto &resp = route_get("/content/about-us");

    EXPECT_EQ(resp.status(), qb::http::status::OK);
    EXPECT_EQ(resp.body().template as<std::string>(), "Page: about-us");
}

TEST_F(RoutingMatchTest, EmptySegmentDoesNotSatisfyParameter) {
    // `/files//details` collapses the empty `//` segment, so the :filename param
    // never binds and the route cannot match -> 404. (Contract-coupled: pins the
    // empty-segment normalization behaviour.)
    router.get("/files/:filename/details", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "File: " + ctx->path_param("filename");
        ctx->complete();
    });

    auto &resp = route_get("/files//details");

    EXPECT_EQ(resp.status(), qb::http::status::NOT_FOUND);
    EXPECT_EQ(session->response_write_count(), 1u);
}

// --------------------------------------------------------------------------
// Wildcard matching
// --------------------------------------------------------------------------

TEST_F(RoutingMatchTest, WildcardCapturesRemainingPath) {
    router.get("/files/*filepath", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "File: " + ctx->path_param("filepath");
        ctx->complete();
    });
    router.compile();

    // Multi-segment capture.
    router.route(session, create_request(qb::http::method::GET, "/files/documents/report.pdf"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "File: documents/report.pdf");

    session->reset();

    // Single-segment capture.
    router.route(session, create_request(qb::http::method::GET, "/files/image.png"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "File: image.png");
}

TEST_F(RoutingMatchTest, WildcardAtRootCapturesWholePath) {
    router.get("/*filepath", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "Root wildcard: " + ctx->path_param("filepath");
        ctx->complete();
    });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/some/path.html"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "Root wildcard: some/path.html");

    session->reset();

    router.route(session, create_request(qb::http::method::GET, "/another.txt"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "Root wildcard: another.txt");
}

TEST_F(RoutingMatchTest, WildcardConsumingNothingYieldsEmptyCapture) {
    // `/archive/` and `/archive` both leave the *subpath wildcard empty.
    // (Contract-coupled: pins the "wildcard may capture zero segments" behaviour.)
    router.get("/archive/*subpath", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "Archive subpath: [" + ctx->path_param("subpath") + "]";
        ctx->complete();
    });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/archive/"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "Archive subpath: []");

    session->reset();

    router.route(session, create_request(qb::http::method::GET, "/archive"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "Archive subpath: []");
}

// --------------------------------------------------------------------------
// Precedence: static > parameter > wildcard
// --------------------------------------------------------------------------

TEST_F(RoutingMatchTest, StaticRouteWinsOverWildcardOnSamePrefix) {
    router.get("/data/specific", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "static";
        ctx->complete();
    });
    router.get("/data/*whatever", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "wildcard: " + ctx->path_param("whatever");
        ctx->complete();
    });
    router.compile();

    // Exact static path -> static handler wins.
    router.route(session, create_request(qb::http::method::GET, "/data/specific"));
    EXPECT_EQ(session->_response.body().template as<std::string>(), "static");

    session->reset();

    // Non-matching static -> falls through to wildcard.
    router.route(session, create_request(qb::http::method::GET, "/data/general/info"));
    EXPECT_EQ(session->_response.body().template as<std::string>(), "wildcard: general/info");
}

TEST_F(RoutingMatchTest, ParameterRouteWinsOverWildcardOnSamePrefix) {
    router.get("/api/:version/info", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "version: " + ctx->path_param("version");
        ctx->complete();
    });
    router.get("/api/*path", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "wildcard: " + ctx->path_param("path");
        ctx->complete();
    });
    router.compile();

    // Structurally matches the parameter route -> parameter wins over wildcard.
    router.route(session, create_request(qb::http::method::GET, "/api/v2/info"));
    EXPECT_EQ(session->_response.body().template as<std::string>(), "version: v2");

    session->reset();

    // Does not fit the parameter shape -> wildcard catches it.
    router.route(session, create_request(qb::http::method::GET, "/api/v1/status/all"));
    EXPECT_EQ(session->_response.body().template as<std::string>(), "wildcard: v1/status/all");
}

// --------------------------------------------------------------------------
// `[`, `]` and `|`, which a browser sends as they are: the octet and its percent-encoding name one route (Huly
// QB-1187)
// --------------------------------------------------------------------------

/// A request whose target was read as the server reads one (qb::io::uri::origin_form()): `create_request()` reads a
/// URI reference, which refuses `[`, `]` and `|` in a path.
qb::http::Request
request_as_received(qb::http::method method, std::string const &target) {
    qb::http::Request req;
    req.method() = method;
    req.uri()    = qb::io::uri::origin_form(target);
    EXPECT_TRUE(req.uri().is_valid()) << target;
    req.major_version = 1;
    req.minor_version = 1;
    return req;
}

TEST_F(RoutingMatchTest, ARawOctetAndItsPercentEncodingNameOneRoute) {
    const auto answer = [](std::string tag, std::string param = {}) {
        return [tag = std::move(tag), param = std::move(param)](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = param.empty() ? std::string{tag} : tag + "=" + ctx->path_param(param);
            ctx->complete();
        };
    };
    router.get("/raw/a|b[c]", answer("raw"));
    router.get("/encoded/%5Bx%5D%7c", answer("encoded"));
    router.get("/param/:v", answer("param", "v"));
    router.get("/wild/*rest", answer("wild", "rest"));
    router.post("/post-only/a|b", answer("post"));
    router.get("/named/:v%7C", answer("named", "v%7C"));
    router.compile();

    struct Case {
        qb::http::method method;
        std::string      target;
        qb::http::status status;
        std::string      body;
    };
    const auto GET  = qb::http::method::GET;
    const auto OK   = qb::http::status::OK;
    const auto NONE = qb::http::status::NOT_FOUND;
    for (auto const &c : std::vector<Case>{
             // a route registered with the octets: reached by them, by their encodings in either case, by a mix
             {GET, "/raw/a|b[c]", OK, "raw"},
             {GET, "/raw/a%7Cb%5Bc%5D", OK, "raw"},
             {GET, "/raw/a%7cb%5bc%5d", OK, "raw"},
             {GET, "/raw/a|b%5Bc]", OK, "raw"},
             // a route registered with the encodings: reached by the octets as well
             {GET, "/encoded/[x]|", OK, "encoded"},
             {GET, "/encoded/%5Bx%5D%7C", OK, "encoded"},
             {GET, "/encoded/[x%5D%7c", OK, "encoded"},
             // a parameter is the decoded segment, one decoding: `%257C` is `%7C`, never `|`
             {GET, "/param/a|b", OK, "param=a|b"},
             {GET, "/param/a%7Cb", OK, "param=a|b"},
             {GET, "/param/a%257Cb", OK, "param=a%7Cb"},
             {GET, "/param/%5B%2F%5D", OK, "param=[/]"},
             {GET, "/wild/x/a%7Cb/[y]", OK, "wild=x/a|b/[y]"},
             // `%25` is a percent sign: `%257C` names no `|`, `%%7C` a stray `%` and then one
             {GET, "/raw/a%257Cb%5Bc%5D", NONE, ""},
             {GET, "/raw/a%%7Cb[c]", NONE, ""},
             // an encoded `/` is no separator, whatever octet it stands beside
             {GET, "/raw%2Fa|b[c]", NONE, ""},
             // the method a path allows is found by either spelling
             {GET, "/post-only/a|b", qb::http::status::METHOD_NOT_ALLOWED, ""},
             {GET, "/post-only/a%7Cb", qb::http::status::METHOD_NOT_ALLOWED, ""},
             {qb::http::method::POST, "/post-only/a%7cb", OK, "post"},
             // a capture's name is kept as written: only a static segment is matched in either spelling
             {GET, "/named/x|y", OK, "named=x|y"}
         }) {
        session->reset();
        router.route(session, request_as_received(c.method, c.target));
        EXPECT_EQ(session->_response.status(), c.status) << c.target;
        if (c.status == OK) {
            EXPECT_EQ(session->_response.body().template as<std::string>(), c.body) << c.target;
        }
    }
}

// A route's pattern names it with the octets, whichever spelling registered it, its captures as written: the label a
// metric or an access log reads in ctx->route_pattern() (Huly QB-1187).
TEST_F(RoutingMatchTest, ARoutePatternNamesTheOctetsWhicheverSpellingRegisteredIt) {
    const auto pattern = [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = std::string{ctx->route_pattern()};
        ctx->complete();
    };
    router.get("/encoded/%5Bx%5D%7c/:v%7C", pattern);
    router.get("/raw/a|b", pattern);
    router.compile();
    for (auto const &[target, expected] : std::vector<std::pair<std::string, std::string>>{
             {"/encoded/[x]|/1", "/encoded/[x]|/:v%7C"},
             {"/encoded/%5Bx%5D%7C/1", "/encoded/[x]|/:v%7C"},
             {"/raw/a%7Cb", "/raw/a|b"},
             {"/raw/a|b", "/raw/a|b"}
         }) {
        session->reset();
        router.route(session, request_as_received(qb::http::method::GET, target));
        EXPECT_EQ(session->_response.status(), qb::http::status::OK) << target;
        EXPECT_EQ(session->_response.body().template as<std::string>(), expected) << target;
    }
}

} // namespace

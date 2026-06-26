/**
 * @file qbm/http/tests/unit/routing/router-match.cpp
 * @brief Canonical, exhaustive specification of the radix-tree route matcher.
 *
 * This is the authority for *how a path is matched to a route* in qb-http:
 * static vs. parameter vs. wildcard segments, precedence between them, path-
 * parameter percent-decoding, multi-slash / empty-segment normalization, the
 * 405-with-`Allow` path for an existing path reached by an unregistered method,
 * and the structural prefix/extension mismatch cases.
 *
 * Flow under test: `Router::route(session, request)` splits the request target
 * into segments, walks the compiled @ref qb::http::RadixTree, binds path
 * parameters, percent-decodes them (`%20`→space, `%2F`→`/`, '+' stays literal),
 * and dispatches the matched handler — which (via @ref make_verifying_handler)
 * marks the session, snapshots the decoded params, and finalizes 200 OK. A miss
 * yields 404; a path-hit/method-miss yields 405 with a sorted `Allow` header.
 *
 * Precedence and decoding case-lists are expressed as `TEST_P` tables so each
 * row is an independently-reported case. The shared @ref qb::http::test
 * scaffolding (MockSession, create_request, make_verifying_handler) replaces the
 * former inline copies.
 *
 * Pure logic: no event loop, no socket, no timing.
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

#include "../../shared/mock_session.h"

using qb::http::test::create_request;
using qb::http::test::make_verifying_handler;
using qb::http::test::MockSession;

// ---------------------------------------------------------------------------
// Shared fixture: a fresh MockSession + Router per test, with thin helpers.
// ---------------------------------------------------------------------------
class RouterMatchTest : public ::testing::Test {
protected:
    std::shared_ptr<MockSession>  mock_session;
    qb::http::Router<MockSession> router;

    void
    SetUp() override {
        mock_session = std::make_shared<MockSession>();
    }

    /** @brief Routes @p method @p path through the router into the mock session. */
    void
    route(qb::http::method method, const std::string &path) {
        router.route(mock_session, create_request(method, path));
    }

    /** @brief Returns the decoded value of captured path parameter @p name, or empty. */
    [[nodiscard]] std::string
    param(const std::string &name) const {
        auto v = mock_session->_captured_params.get(name);
        return v.has_value() ? std::string(v.value()) : std::string{};
    }
};

// ===========================================================================
// Basic static route matching
// ===========================================================================
TEST_F(RouterMatchTest, StaticRouteSimpleMatch) {
    router.get("/hello", make_verifying_handler<MockSession>("hello_handler"));
    router.compile();

    route(HTTP_GET, "/hello");

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "hello_handler");
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
}

TEST_F(RouterMatchTest, StaticRouteNoMatchYields404) {
    router.get("/world", make_verifying_handler<MockSession>("world_handler"));
    router.compile();

    route(HTTP_GET, "/other");

    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, StaticRouteRootPath) {
    router.get("/", make_verifying_handler<MockSession>("root_handler"));
    router.compile();

    route(HTTP_GET, "/");

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "root_handler");
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
}

TEST_F(RouterMatchTest, TrailingSlashEquivalence) {
    // Contract pin: split_path_to_segments treats "/path" and "/path/" as the
    // single segment {"path"}, so one registration matches both forms.
    router.get("/path", make_verifying_handler<MockSession>("path_handler"));
    router.compile();

    route(HTTP_GET, "/path/");
    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "path_handler");
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);

    mock_session->reset();
    route(HTTP_GET, "/path");
    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "path_handler");
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
}

TEST_F(RouterMatchTest, StaticRouteIsCaseSensitive) {
    router.get("/casepath", make_verifying_handler<MockSession>("correct_case_handler"));
    router.compile();

    route(HTTP_GET, "/casepath");
    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "correct_case_handler");

    mock_session->reset();
    route(HTTP_GET, "/CasePath");
    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, MultipleConsecutiveSlashesAreCollapsed) {
    // "/foo///bar" normalizes to {"foo","bar"} via split_path_to_segments.
    router.get("/foo/bar", make_verifying_handler<MockSession>("foo_bar_handler"));
    router.compile();

    route(HTTP_GET, "/foo///bar");

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "foo_bar_handler");
}

// ===========================================================================
// Parameter matching + path-parameter decoding (TABLE)
// ===========================================================================
TEST_F(RouterMatchTest, ParameterSimpleMatch) {
    router.get("/users/:id", make_verifying_handler<MockSession>("user_id_handler"));
    router.compile();

    route(HTTP_GET, "/users/123");

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "user_id_handler");
    EXPECT_EQ(param("id"), "123");
}

TEST_F(RouterMatchTest, MultipleParameters) {
    router.get("/articles/:category/posts/:postId", make_verifying_handler<MockSession>("article_post_handler"));
    router.compile();

    route(HTTP_GET, "/articles/tech/posts/456");

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "article_post_handler");
    EXPECT_EQ(param("category"), "tech");
    EXPECT_EQ(param("postId"), "456");
}

TEST_F(RouterMatchTest, ConsecutiveParameterSegments) {
    router.get("/:tenant/:resource", make_verifying_handler<MockSession>("double_param_handler"));
    router.compile();

    route(HTTP_GET, "/acme/users");

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(param("tenant"), "acme");
    EXPECT_EQ(param("resource"), "users");
}

TEST_F(RouterMatchTest, ParameterFollowedByStaticSegment) {
    router.get("/item/:itemId/details", make_verifying_handler<MockSession>("item_details_handler"));
    router.compile();

    route(HTTP_GET, "/item/item007/details");

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(param("itemId"), "item007");
}

TEST_F(RouterMatchTest, ParameterNameWithHyphen) {
    router.get("/item/:item-id/info", make_verifying_handler<MockSession>("item_hyphen_id_handler"));
    router.compile();

    route(HTTP_GET, "/item/product-abc/info");

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(param("item-id"), "product-abc");
}

// --- Parameter decoding table ----------------------------------------------
//
// Contract (router_core decode_path_parameters → utility::decode_path_component):
//   * %HH is percent-decoded (%20→space, %2B→'+', %2F→'/').
//   * '+' is kept LITERAL in path components (the WHATWG path rule; only query/
//     form decoding maps '+'→space).
//   * %2F decodes to a literal '/' INSIDE the bound parameter value — it does
//     NOT split the segment, because splitting happens on the raw (still-encoded)
//     target before decoding.
struct ParamDecodeRow {
    std::string raw_value;     ///< value placed in the request target after /users/
    std::string decoded_value; ///< expected decoded parameter value
    std::string label;
};

class ParamDecode : public RouterMatchTest, public ::testing::WithParamInterface<ParamDecodeRow> {};

TEST_P(ParamDecode, DecodesPathParameter) {
    const auto &row = GetParam();
    router.get("/users/:id", make_verifying_handler<MockSession>("user_id_handler"));
    router.compile();

    route(HTTP_GET, "/users/" + row.raw_value);

    ASSERT_TRUE(mock_session->_handler_executed) << row.label;
    EXPECT_EQ(param("id"), row.decoded_value) << row.label;
}

INSTANTIATE_TEST_SUITE_P(
    Decoding, ParamDecode,
    ::testing::Values(ParamDecodeRow{"plain", "plain", "plain"}, ParamDecodeRow{"a+b", "a+b", "literal_plus_kept"},
                      ParamDecodeRow{"a%2Bb", "a+b", "encoded_plus"}, ParamDecodeRow{"a%20b", "a b", "encoded_space"},
                      ParamDecodeRow{"a%2Fb", "a/b", "encoded_slash_in_param"},
                      ParamDecodeRow{"a%2fb", "a/b", "encoded_slash_lowercase_hex"},
                      ParamDecodeRow{"%41%42%43", "ABC", "all_encoded"},
                      ParamDecodeRow{"trailing%", "trailing%", "bare_percent_kept_literal"}),
    [](const ::testing::TestParamInfo<ParamDecodeRow> &i) { return i.param.label; });

TEST_F(RouterMatchTest, ParameterMissingFollowingStaticSegmentYields404) {
    router.get("/item/:itemId/details", make_verifying_handler<MockSession>("item_details_handler"));
    router.compile();

    route(HTTP_GET, "/item/item007"); // missing "/details"

    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, EmptyParameterSegmentYields404) {
    // "/api/query//show" collapses to {"api","query","show"} — 3 segments — which
    // does not satisfy the 4-segment "/api/query/:value/show" route.
    router.get("/api/query/:value/show", make_verifying_handler<MockSession>("query_value_handler"));
    router.compile();

    route(HTTP_GET, "/api/query//show");

    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, VeryLongParameterValue) {
    router.get("/content/:itemId/show", make_verifying_handler<MockSession>("long_param_handler"));
    router.compile();

    std::string long_value(500, 'a');
    long_value += "-";
    for (int i = 0; i < 20; ++i) {
        long_value += "segment" + std::to_string(i) + "_";
    }
    long_value.pop_back();

    route(HTTP_GET, "/content/" + long_value + "/show");

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(param("itemId"), long_value);
}

// ===========================================================================
// Wildcard matching
// ===========================================================================
TEST_F(RouterMatchTest, WildcardSimpleMatch) {
    router.get("/files/*filepath", make_verifying_handler<MockSession>("files_wildcard_handler"));
    router.compile();

    route(HTTP_GET, "/files/documents/report.pdf");

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "files_wildcard_handler");
    EXPECT_EQ(param("filepath"), "documents/report.pdf");
}

TEST_F(RouterMatchTest, WildcardAtRoot) {
    router.get("/*anypath", make_verifying_handler<MockSession>("root_wildcard_handler"));
    router.compile();

    route(HTTP_GET, "/some/long/path/to/resource.html");

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(param("anypath"), "some/long/path/to/resource.html");
}

TEST_F(RouterMatchTest, WildcardConsumingNothing) {
    // Contract pin: a "/archive/*subpath" route matches both "/archive/" and
    // "/archive" with an EMPTY capture.
    router.get("/archive/*subpath", make_verifying_handler<MockSession>("archive_empty_wildcard"));
    router.compile();

    route(HTTP_GET, "/archive/");
    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(param("subpath"), "");

    mock_session->reset();
    route(HTTP_GET, "/archive");
    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(param("subpath"), "");
}

TEST_F(RouterMatchTest, WildcardUnderParameterSegment) {
    router.get("/:tenant/*rest", make_verifying_handler<MockSession>("param_wildcard_handler"));
    router.compile();

    route(HTTP_GET, "/acme/api/v1/users");

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(param("tenant"), "acme");
    EXPECT_EQ(param("rest"), "api/v1/users");
}

TEST_F(RouterMatchTest, VeryLongWildcardCapture) {
    router.get("/assets/*filePath", make_verifying_handler<MockSession>("long_wildcard_handler"));
    router.compile();

    std::string long_path = "a";
    for (int i = 0; i < 50; ++i) {
        long_path += "/" + std::string(1, static_cast<char>('b' + (i % 24)));
    }
    long_path += "/final_file_with_long_name_and_extension.testdata";

    route(HTTP_GET, "/assets/" + long_path);

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(param("filePath"), long_path);
}

// ===========================================================================
// Precedence / specificity (TABLE)
// ===========================================================================
//
// A router registered with one static, one parameter and one wildcard route at
// the same level must prefer the MOST SPECIFIC: static > parameter > wildcard.
// Each row drives one request and asserts which handler won (+ any capture).
struct PrecedenceRow {
    std::string request_path;
    std::string expected_handler;
    std::string capture_name;  ///< empty when the winner captures nothing
    std::string capture_value;
    std::string label;
};

class Precedence : public RouterMatchTest, public ::testing::WithParamInterface<PrecedenceRow> {
protected:
    void
    SetUp() override {
        RouterMatchTest::SetUp();
        // Same level: static, parameter, then catch-all wildcard.
        router.get("/r/specific", make_verifying_handler<MockSession>("static"));
        router.get("/r/:id", make_verifying_handler<MockSession>("param"));
        router.get("/r/*rest", make_verifying_handler<MockSession>("wildcard"));
        router.compile();
    }
};

TEST_P(Precedence, MostSpecificWins) {
    const auto &row = GetParam();
    route(HTTP_GET, row.request_path);

    ASSERT_TRUE(mock_session->_handler_executed) << row.label;
    EXPECT_EQ(mock_session->_handler_id, row.expected_handler) << row.label;
    if (!row.capture_name.empty()) {
        EXPECT_EQ(param(row.capture_name), row.capture_value) << row.label;
    }
}

INSTANTIATE_TEST_SUITE_P(
    StaticParamWildcard, Precedence,
    ::testing::Values(PrecedenceRow{"/r/specific", "static", "", "", "static_beats_param_and_wildcard"},
                      PrecedenceRow{"/r/123", "param", "id", "123", "param_beats_wildcard"},
                      PrecedenceRow{"/r/a/b/c", "wildcard", "rest", "a/b/c", "wildcard_catches_multi_segment"},
                      PrecedenceRow{"/r", "wildcard", "rest", "", "wildcard_catches_empty_at_prefix"}),
    [](const ::testing::TestParamInfo<PrecedenceRow> &i) { return i.param.label; });

// Greedy-vs-specific: a specific deeper route must be reachable even though a
// shallower wildcard could also have matched the same prefix.
TEST_F(RouterMatchTest, GreedyWildcardYieldsToSpecificDeeperRoute) {
    router.get("/api/*rest", make_verifying_handler<MockSession>("greedy_wildcard"));
    router.get("/api/v1/status", make_verifying_handler<MockSession>("specific_status"));
    router.get("/api/:version/users", make_verifying_handler<MockSession>("param_users"));
    router.compile();

    // Exact deep static beats the shallow wildcard.
    route(HTTP_GET, "/api/v1/status");
    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "specific_status");

    // Parameter route beats the wildcard for the matching shape.
    mock_session->reset();
    route(HTTP_GET, "/api/v2/users");
    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "param_users");
    EXPECT_EQ(param("version"), "v2");

    // Anything the specific routes do not cover falls through to the wildcard.
    mock_session->reset();
    route(HTTP_GET, "/api/v1/orders/42");
    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "greedy_wildcard");
    EXPECT_EQ(param("rest"), "v1/orders/42");
}

TEST_F(RouterMatchTest, RootStaticVsRootWildcard) {
    router.get("/", make_verifying_handler<MockSession>("static_root"));
    router.get("/*filepath", make_verifying_handler<MockSession>("wildcard_root"));
    router.compile();

    route(HTTP_GET, "/");
    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "static_root");

    mock_session->reset();
    route(HTTP_GET, "/somefile.txt");
    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "wildcard_root");
    EXPECT_EQ(param("filepath"), "somefile.txt");
}

TEST_F(RouterMatchTest, ComplexMixedSegments) {
    router.get("/data/:user/details/*itemPath", make_verifying_handler<MockSession>("complex_mix"));
    router.compile();

    route(HTTP_GET, "/data/user123/details/path/to/item.json");

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "complex_mix");
    EXPECT_EQ(param("user"), "user123");
    EXPECT_EQ(param("itemPath"), "path/to/item.json");
}

// ===========================================================================
// Duplicate route registration
// ===========================================================================
//
// Registering the same method+path twice: the matcher must still resolve to a
// single, deterministic handler (last registration wins) rather than crashing,
// double-dispatching, or returning ambiguity.
TEST_F(RouterMatchTest, DuplicateRouteLastRegistrationWins) {
    router.get("/dup", make_verifying_handler<MockSession>("first"));
    router.get("/dup", make_verifying_handler<MockSession>("second"));
    router.compile();

    route(HTTP_GET, "/dup");

    ASSERT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "second");
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    // Exactly one response was finalized (MockSession throws on a second write).
    EXPECT_EQ(mock_session->response_write_count(), 1u);
}

TEST_F(RouterMatchTest, DuplicateParameterRouteLastRegistrationWins) {
    router.get("/u/:id", make_verifying_handler<MockSession>("param_first"));
    router.get("/u/:id", make_verifying_handler<MockSession>("param_second"));
    router.compile();

    route(HTTP_GET, "/u/77");

    ASSERT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "param_second");
    EXPECT_EQ(param("id"), "77");
    EXPECT_EQ(mock_session->response_write_count(), 1u);
}

// ===========================================================================
// Method-specific matching + 405 / Allow
// ===========================================================================
TEST_F(RouterMatchTest, DifferentMethodsSamePathDispatchIndependently) {
    router.get("/resource", make_verifying_handler<MockSession>("get_resource"));
    router.post("/resource", make_verifying_handler<MockSession>("post_resource"));
    router.compile();

    route(HTTP_GET, "/resource");
    EXPECT_EQ(mock_session->_handler_id, "get_resource");

    mock_session->reset();
    route(HTTP_POST, "/resource");
    EXPECT_EQ(mock_session->_handler_id, "post_resource");

    // PUT: path exists but method not registered → 405 with sorted Allow.
    mock_session->reset();
    route(HTTP_PUT, "/resource");
    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_METHOD_NOT_ALLOWED);
    EXPECT_EQ(mock_session->_response.header("Allow"), "GET, POST");
}

TEST_F(RouterMatchTest, MethodNotAllowedOnParameterizedPath) {
    router.get("/resource/:id", make_verifying_handler<MockSession>("get_resource_id"));
    router.put("/resource/:id", make_verifying_handler<MockSession>("put_resource_id"));
    router.compile();

    route(HTTP_GET, "/resource/123");
    EXPECT_EQ(mock_session->_handler_id, "get_resource_id");
    EXPECT_EQ(param("id"), "123");

    mock_session->reset();
    route(HTTP_PUT, "/resource/456");
    EXPECT_EQ(mock_session->_handler_id, "put_resource_id");
    EXPECT_EQ(param("id"), "456");

    // DELETE not registered for that shape → 405 + Allow.
    mock_session->reset();
    route(HTTP_DELETE, "/resource/789");
    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_METHOD_NOT_ALLOWED);
    EXPECT_EQ(mock_session->_response.header("Allow"), "GET, PUT");
}

TEST_F(RouterMatchTest, MethodNotAllowedKeepsDecodedPathParamsForMiddleware) {
    // Global middleware must see the decoded path params even on the 405 path.
    router.use([](auto ctx, auto next) {
        if (ctx->session()) {
            ctx->session()->_captured_params = ctx->path_parameters();
        }
        next();
    });
    router.get("/resource/:id", make_verifying_handler<MockSession>("get_resource_id"));
    router.compile();

    route(HTTP_PATCH, "/resource/a+b");

    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_METHOD_NOT_ALLOWED);
    EXPECT_EQ(param("id"), "a+b");
}

TEST_F(RouterMatchTest, AllowHeaderMergesAcrossParamAndStaticBranches) {
    router.get("/resource/:id", make_verifying_handler<MockSession>("get_resource_id"));
    router.post("/resource/static", make_verifying_handler<MockSession>("post_resource_static"));
    router.compile();

    // GET hits the param branch.
    route(HTTP_GET, "/resource/static");
    EXPECT_EQ(mock_session->_handler_id, "get_resource_id");

    // POST hits the static branch.
    mock_session->reset();
    route(HTTP_POST, "/resource/static");
    EXPECT_EQ(mock_session->_handler_id, "post_resource_static");

    // PUT on the shared path → 405 whose Allow merges both branches' methods.
    mock_session->reset();
    route(HTTP_PUT, "/resource/static");
    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_METHOD_NOT_ALLOWED);
    EXPECT_EQ(mock_session->_response.header("Allow"), "GET, POST");
}

TEST_F(RouterMatchTest, IdenticalWildcardPathDifferentMethods) {
    router.get("/assets/*details", make_verifying_handler<MockSession>("get_assets_details"));
    router.post("/assets/*details", make_verifying_handler<MockSession>("post_assets_details"));
    router.compile();

    route(HTTP_GET, "/assets/js/app.js");
    EXPECT_EQ(mock_session->_handler_id, "get_assets_details");
    EXPECT_EQ(param("details"), "js/app.js");

    mock_session->reset();
    route(HTTP_POST, "/assets/css/theme.css");
    EXPECT_EQ(mock_session->_handler_id, "post_assets_details");
    EXPECT_EQ(param("details"), "css/theme.css");
}

// 405 on a path that only a WILDCARD route covers: the Allow header must be
// assembled from the wildcard branch of allowed_methods (the multi-segment
// capture path), proving the wildcard contributes its methods to the merge.
TEST_F(RouterMatchTest, MethodNotAllowedOnWildcardOnlyPathMergesWildcardMethods) {
    router.get("/static/*path", make_verifying_handler<MockSession>("get_static"));
    router.post("/static/*path", make_verifying_handler<MockSession>("post_static"));
    router.compile();

    // GET/POST dispatch normally through the wildcard.
    route(HTTP_GET, "/static/js/app.js");
    EXPECT_EQ(mock_session->_handler_id, "get_static");

    // DELETE is unregistered for the wildcard path → 405 whose Allow lists the
    // wildcard branch's methods (this drives the multi-segment wildcard merge).
    mock_session->reset();
    route(HTTP_DELETE, "/static/css/site/theme.css");
    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_METHOD_NOT_ALLOWED);
    EXPECT_EQ(mock_session->_response.header("Allow"), "GET, POST");
}

// 405 where the request terminates exactly at the node owning a wildcard child
// (the "/x/" base-case): allowed_methods must fold in the wildcard child's
// methods via its empty-capture branch.
TEST_F(RouterMatchTest, MethodNotAllowedAtWildcardParentNodeMergesEmptyCapture) {
    router.get("/dl/*rest", make_verifying_handler<MockSession>("get_dl"));
    router.put("/dl/*rest", make_verifying_handler<MockSession>("put_dl"));
    router.compile();

    // "/dl" terminates at the parent of the wildcard child (empty capture).
    route(HTTP_DELETE, "/dl");
    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_METHOD_NOT_ALLOWED);
    EXPECT_EQ(mock_session->_response.header("Allow"), "GET, PUT");
}

// ===========================================================================
// Structural prefix / extension mismatches and empty router
// ===========================================================================
TEST_F(RouterMatchTest, NoRoutesDefinedYields404) {
    router.compile();

    route(HTTP_GET, "/anypath");

    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, PathIsPrefixOfStaticRoute) {
    router.get("/alpha/beta/gamma", make_verifying_handler<MockSession>("static_abc_handler"));
    router.compile();

    route(HTTP_GET, "/alpha/beta");

    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, PathIsPrefixOfParameterRoute) {
    router.get("/user/:userId/profile", make_verifying_handler<MockSession>("user_profile_handler"));
    router.compile();

    route(HTTP_GET, "/user/testuser");

    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, PathIsExtensionOfStaticRoute) {
    router.get("/data/source", make_verifying_handler<MockSession>("data_source_handler"));
    router.compile();

    route(HTTP_GET, "/data/source/extra");

    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, PathIsExtensionOfParameterRoute) {
    router.get("/product/:productId", make_verifying_handler<MockSession>("product_handler"));
    router.compile();

    route(HTTP_GET, "/product/p123/details");

    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);
}

// ===========================================================================
// RouterCore guard rails: oversize path + clear()/recompile recovery
// ===========================================================================

TEST_F(RouterMatchTest, OversizePathYields400BadRequest) {
    // RouterCore caps the request path at 4096 chars to bound allocations; a
    // longer path short-circuits to 400 before the radix walk (no handler runs).
    router.get("/files/*rest", make_verifying_handler<MockSession>("files_handler"));
    router.compile();

    std::string long_path = "/files/" + std::string(5000, 'a');
    route(HTTP_GET, long_path);

    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_BAD_REQUEST);
    EXPECT_EQ(mock_session->_response.body().as<std::string>(), "Path too long");
}

TEST_F(RouterMatchTest, PathAtMaxLengthBoundaryStillRoutes) {
    // A path exactly at the 4096-char boundary is still served (the guard is a
    // strict `> MAX_PATH_LENGTH`).
    router.get("/files/*rest", make_verifying_handler<MockSession>("files_handler_ok"));
    router.compile();

    // "/files/" is 7 chars; pad to exactly 4096 total.
    std::string at_limit = "/files/" + std::string(4096 - 7, 'b');
    ASSERT_EQ(at_limit.size(), 4096u);
    route(HTTP_GET, at_limit);

    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
}

TEST_F(RouterMatchTest, ClearRemovesRoutesAndRecompileServesAgain) {
    router.get("/old", make_verifying_handler<MockSession>("old_handler"));
    router.compile();
    route(HTTP_GET, "/old");
    EXPECT_TRUE(mock_session->_handler_executed);

    // clear() drops all routes + resets special handlers to defaults.
    router.clear();
    router.compile();

    mock_session = std::make_shared<MockSession>();
    route(HTTP_GET, "/old");
    EXPECT_FALSE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);

    // Router remains usable: register + compile + serve a fresh route.
    router.get("/new", make_verifying_handler<MockSession>("new_handler"));
    router.compile();
    mock_session = std::make_shared<MockSession>();
    route(HTTP_GET, "/new");
    EXPECT_TRUE(mock_session->_handler_executed);
    EXPECT_EQ(mock_session->_handler_id, "new_handler");
    EXPECT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
}

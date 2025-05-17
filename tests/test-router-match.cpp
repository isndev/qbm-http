#include <gtest/gtest.h>
#include "../http.h" // Provides qb::http::Router, Request, Response, Context, PathParameters, etc.
#include <qb/uuid.h> // For qb::uuid and qb::generate_random_uuid
#include <memory>
#include <string>
#include <utility> // For std::move
#include <optional> // For std::optional, if used by PathParameters or Context

// Minimal Mock Session for match testing
struct MatchTestSession {
    qb::http::Response _response;
    bool _handler_executed = false;
    std::string _handler_id; // To identify which handler was called
    qb::http::PathParameters _captured_params;
    qb::uuid _session_id = qb::generate_random_uuid(); // Assuming qb::generate_random_uuid available via http.h

    qb::http::Response& get_response_ref() { return _response; }

    MatchTestSession& operator<<(const qb::http::Response& resp) {
        _response = resp;
        // In match tests, we don't focus on multiple writes like in full router tests.
        return *this;
    }
    
    [[nodiscard]] const qb::uuid& id() const { return _session_id; }

    void reset() {
        _response = qb::http::Response();
        _handler_executed = false;
        _handler_id.clear();
        _captured_params.clear(); // Assuming PathParameters has a clear method or can be reassigned
    }
};

// Test Fixture for Router Matching Tests
class RouterMatchTest : public ::testing::Test {
protected:
    std::shared_ptr<MatchTestSession> mock_session;
    qb::http::Router<MatchTestSession> router;

    void SetUp() override {
        mock_session = std::make_shared<MatchTestSession>();
        router = qb::http::Router<MatchTestSession>(); // Fresh router for each test
    }

    ~RouterMatchTest() noexcept override = default; // Explicitly noexcept(true)

    qb::http::Request create_request(qb::http::method method_val, const std::string& target_path) {
        qb::http::Request req;
        req.method = method_val;
        try {
            req.uri() = qb::io::uri(target_path);
        } catch (const std::exception& e) {
            ADD_FAILURE() << "Failed to parse URI: " << target_path << " - " << e.what();
            // Return a request that's unlikely to match anything to prevent further issues
            req.uri() = qb::io::uri("/__invalid_uri_due_to_parse_failure__");
        }
        req.major_version = 1;
        req.minor_version = 1;
        return req;
    }

    // Helper to define a simple handler that marks execution and captures params
    auto
    make_verifying_handler(const std::string& handler_id) {
        return [this, handler_id](auto ctx) {
            if (ctx->session()) {
                ctx->session()->_handler_executed = true;
                ctx->session()->_handler_id = handler_id;
                ctx->session()->_captured_params = ctx->path_parameters();
            }
            ctx->response().status_code = HTTP_STATUS_OK; // Indicate a match and successful handling
            ctx->complete();
        };
    }
};

// --- Basic Static Route Matching ---
TEST_F(RouterMatchTest, StaticRouteSimpleMatch) {
    router.get("/hello", make_verifying_handler("hello_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/hello");
    router.route(mock_session, std::move(request));

    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "hello_handler");
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
}

TEST_F(RouterMatchTest, StaticRouteNoMatch) {
    router.get("/world", make_verifying_handler("world_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/other");
    router.route(mock_session, std::move(request));

    ASSERT_FALSE(mock_session->_handler_executed); // Handler for /world should not run
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND); // Default 404
}

TEST_F(RouterMatchTest, StaticRouteRootPath) {
    router.get("/", make_verifying_handler("root_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/");
    router.route(mock_session, std::move(request));

    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "root_handler");
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
}

TEST_F(RouterMatchTest, StaticRouteTrailingSlashEquivalence) {
    // RadixTree's split_path_to_segments treats "/path" and "/path/" as {"path"}
    // So a single definition should match both if router doesn't add its own normalization layer
    // that distinguishes them before the tree.
    router.get("/path", make_verifying_handler("path_handler"));
    router.compile();

    // Test with trailing slash
    mock_session->reset();
    auto request_with_slash = create_request(HTTP_GET, "/path/");
    router.route(mock_session, std::move(request_with_slash));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "path_handler");
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);

    // Test without trailing slash
    mock_session->reset();
    auto request_without_slash = create_request(HTTP_GET, "/path");
    router.route(mock_session, std::move(request_without_slash));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "path_handler");
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
}

TEST_F(RouterMatchTest, StaticRouteCaseSensitivity) {
    router.get("/casepath", make_verifying_handler("correct_case_handler"));
    router.compile();

    // Correct case
    mock_session->reset();
    auto request_correct = create_request(HTTP_GET, "/casepath");
    router.route(mock_session, std::move(request_correct));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "correct_case_handler");
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    
    // Incorrect case
    mock_session->reset();
    auto request_incorrect = create_request(HTTP_GET, "/CasePath");
    router.route(mock_session, std::move(request_incorrect));
    ASSERT_FALSE(mock_session->_handler_executed); // Should not execute correct_case_handler
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND);
}

// --- Parameterized Route Matching ---
TEST_F(RouterMatchTest, ParameterSimpleMatch) {
    router.get("/users/:id", make_verifying_handler("user_id_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/users/123");
    router.route(mock_session, std::move(request));

    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "user_id_handler");
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    auto param_val = mock_session->_captured_params.get("id");
    ASSERT_TRUE(param_val.has_value());
    ASSERT_EQ(param_val.value(), "123");
}

TEST_F(RouterMatchTest, ParameterMultipleParams) {
    router.get("/articles/:category/posts/:postId", make_verifying_handler("article_post_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/articles/tech/posts/456");
    router.route(mock_session, std::move(request));
    
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "article_post_handler");
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    
    auto cat_val = mock_session->_captured_params.get("category");
    ASSERT_TRUE(cat_val.has_value());
    ASSERT_EQ(cat_val.value(), "tech");

    auto post_id_val = mock_session->_captured_params.get("postId");
    ASSERT_TRUE(post_id_val.has_value());
    ASSERT_EQ(post_id_val.value(), "456");
}

TEST_F(RouterMatchTest, ParameterAtEndOfPath) {
    router.get("/product/:productId", make_verifying_handler("product_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/product/abc-xyz");
    router.route(mock_session, std::move(request));

    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "product_handler");
    auto param_val = mock_session->_captured_params.get("productId");
    ASSERT_TRUE(param_val.has_value());
    ASSERT_EQ(param_val.value(), "abc-xyz");
}

TEST_F(RouterMatchTest, ParameterWithStaticSegmentAfter) {
    router.get("/item/:itemId/details", make_verifying_handler("item_details_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/item/item007/details");
    router.route(mock_session, std::move(request));

    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "item_details_handler");
    auto param_val = mock_session->_captured_params.get("itemId");
    ASSERT_TRUE(param_val.has_value());
    ASSERT_EQ(param_val.value(), "item007");
}

TEST_F(RouterMatchTest, ParameterMissingFollowingStaticSegment) {
    router.get("/item/:itemId/details", make_verifying_handler("item_details_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/item/item007"); // Missing '/details'
    router.route(mock_session, std::move(request));

    ASSERT_FALSE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, ParameterValueEmptySegment) {
    // Route: /api/query/:value/show
    // Path:  /api/query//show  (empty segment for :value)
    // RadixTree::split_path_to_segments skips empty segments from "//"
    // So, "/api/query//show" becomes {"api", "query", "show"}
    // This will NOT match "/api/query/:value/show" which expects 4 segments from split
    // where the 3rd is the parameter.
    router.get("/api/query/:value/show", make_verifying_handler("query_value_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/api/query//show");
    router.route(mock_session, std::move(request));

    ASSERT_FALSE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND);
}


// --- Wildcard Route Matching ---
TEST_F(RouterMatchTest, WildcardSimpleMatch) {
    router.get("/files/*filepath", make_verifying_handler("files_wildcard_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/files/documents/report.pdf");
    router.route(mock_session, std::move(request));

    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "files_wildcard_handler");
    auto param_val = mock_session->_captured_params.get("filepath");
    ASSERT_TRUE(param_val.has_value());
    ASSERT_EQ(param_val.value(), "documents/report.pdf");
}

TEST_F(RouterMatchTest, WildcardAtRoot) {
    router.get("/*anypath", make_verifying_handler("root_wildcard_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/some/long/path/to/resource.html");
    router.route(mock_session, std::move(request));

    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "root_wildcard_handler");
    auto param_val = mock_session->_captured_params.get("anypath");
    ASSERT_TRUE(param_val.has_value());
    ASSERT_EQ(param_val.value(), "some/long/path/to/resource.html");
}

TEST_F(RouterMatchTest, WildcardConsumingNothing) {
    // Matches if path is "/archive/" or "/archive" and route is "/archive/*sub"
    router.get("/archive/*subpath", make_verifying_handler("archive_empty_wildcard"));
    router.compile();

    // Test with trailing slash
    mock_session->reset();
    auto request_slash = create_request(HTTP_GET, "/archive/");
    router.route(mock_session, std::move(request_slash));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "archive_empty_wildcard");
    auto param_slash = mock_session->_captured_params.get("subpath");
    ASSERT_TRUE(param_slash.has_value());
    ASSERT_EQ(param_slash.value(), "");

    // Test without trailing slash (should also match if RadixTree logic for this is consistent)
    mock_session->reset();
    auto request_no_slash = create_request(HTTP_GET, "/archive");
    router.route(mock_session, std::move(request_no_slash));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "archive_empty_wildcard");
    auto param_no_slash = mock_session->_captured_params.get("subpath");
    ASSERT_TRUE(param_no_slash.has_value());
    ASSERT_EQ(param_no_slash.value(), "");
}

TEST_F(RouterMatchTest, WildcardDoesNotMatchPrefixOnly) {
    // If route is /prefix/*wild and path is just /prefix (no further segments, not even a slash)
    // it should NOT match if wildcards must consume something OR if the structure implies
    // something after prefix (even if empty for wildcard).
    // Our current RadixTree with the "match empty wildcard" logic WILL match this,
    // treating "wild" as empty. This test confirms that.
    router.get("/data/*info", make_verifying_handler("data_wildcard"));
    router.compile();

    auto request = create_request(HTTP_GET, "/data");
    router.route(mock_session, std::move(request));

    ASSERT_TRUE(mock_session->_handler_executed); // Current RadixTree behavior
    ASSERT_EQ(mock_session->_handler_id, "data_wildcard");
    auto param_val = mock_session->_captured_params.get("info");
    ASSERT_TRUE(param_val.has_value());
    ASSERT_EQ(param_val.value(), "");
}

// --- Priority and Precedence Matching ---

TEST_F(RouterMatchTest, StaticOverParameter) {
    router.get("/entity/specific", make_verifying_handler("static_specific"));
    router.get("/entity/:id", make_verifying_handler("param_id"));
    router.compile();

    // Match static
    mock_session->reset();
    auto req_static = create_request(HTTP_GET, "/entity/specific");
    router.route(mock_session, std::move(req_static));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "static_specific");

    // Match parameter
    mock_session->reset();
    auto req_param = create_request(HTTP_GET, "/entity/123");
    router.route(mock_session, std::move(req_param));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "param_id");
    auto param_val = mock_session->_captured_params.get("id");
    ASSERT_TRUE(param_val.has_value());
    ASSERT_EQ(param_val.value(), "123");
}

TEST_F(RouterMatchTest, StaticOverWildcard) {
    router.get("/assets/fixed.js", make_verifying_handler("static_fixed_js"));
    router.get("/assets/*filepath", make_verifying_handler("wildcard_assets"));
    router.compile();

    // Match static
    mock_session->reset();
    auto req_static = create_request(HTTP_GET, "/assets/fixed.js");
    router.route(mock_session, std::move(req_static));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "static_fixed_js");

    // Match wildcard
    mock_session->reset();
    auto req_wildcard = create_request(HTTP_GET, "/assets/css/style.css");
    router.route(mock_session, std::move(req_wildcard));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "wildcard_assets");
    auto param_val = mock_session->_captured_params.get("filepath");
    ASSERT_TRUE(param_val.has_value());
    ASSERT_EQ(param_val.value(), "css/style.css");
}

TEST_F(RouterMatchTest, ParameterOverWildcard) {
    router.get("/api/:version/status", make_verifying_handler("param_version_status"));
    router.get("/api/*everything", make_verifying_handler("wildcard_api"));
    router.compile();

    // Match parameter
    mock_session->reset();
    auto req_param = create_request(HTTP_GET, "/api/v2/status");
    router.route(mock_session, std::move(req_param));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "param_version_status");
    auto param_v = mock_session->_captured_params.get("version");
    ASSERT_TRUE(param_v.has_value());
    ASSERT_EQ(param_v.value(), "v2");

    // Match wildcard
    mock_session->reset();
    auto req_wildcard = create_request(HTTP_GET, "/api/v1/users/list");
    router.route(mock_session, std::move(req_wildcard));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "wildcard_api");
    auto param_e = mock_session->_captured_params.get("everything");
    ASSERT_TRUE(param_e.has_value());
    ASSERT_EQ(param_e.value(), "v1/users/list");
}

// --- Method Specific Matching ---
TEST_F(RouterMatchTest, DifferentMethodsSamePath) {
    router.get("/resource", make_verifying_handler("get_resource"));
    router.post("/resource", make_verifying_handler("post_resource"));
    router.compile();

    // Test GET
    mock_session->reset();
    auto req_get = create_request(HTTP_GET, "/resource");
    router.route(mock_session, std::move(req_get));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "get_resource");

    // Test POST
    mock_session->reset();
    auto req_post = create_request(HTTP_POST, "/resource");
    router.route(mock_session, std::move(req_post));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "post_resource");

    // Test PUT (should be 404 or 405 if router does method checking)
    // Current simple router core gives 404 if no handler for method.
    mock_session->reset();
    auto req_put = create_request(HTTP_PUT, "/resource");
    router.route(mock_session, std::move(req_put));
    ASSERT_FALSE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND);
}

// --- More "Twisted" / Edge Cases for Matching ---

TEST_F(RouterMatchTest, PathWithMultipleConsecutiveSlashes) {
    // /foo///bar should be treated as /foo/bar by split_path_to_segments
    router.get("/foo/bar", make_verifying_handler("foo_bar_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/foo///bar");
    router.route(mock_session, std::move(request));

    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "foo_bar_handler");
}

TEST_F(RouterMatchTest, RootStaticVsRootWildcard) {
    router.get("/", make_verifying_handler("static_root"));
    router.get("/*filepath", make_verifying_handler("wildcard_root"));
    router.compile();

    // Match static root "/"
    mock_session->reset();
    auto req_static_root = create_request(HTTP_GET, "/");
    router.route(mock_session, std::move(req_static_root));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "static_root");

    // Match wildcard root for other paths
    mock_session->reset();
    auto req_wild_path = create_request(HTTP_GET, "/somefile.txt");
    router.route(mock_session, std::move(req_wild_path));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "wildcard_root");
    auto fp = mock_session->_captured_params.get("filepath");
    ASSERT_TRUE(fp.has_value());
    ASSERT_EQ(fp.value(), "somefile.txt");
}

TEST_F(RouterMatchTest, ComplexRouteMix) {
    // /static/:paramA/anotherstatic/*wildcardB
    router.get("/data/:user/details/*itemPath", make_verifying_handler("complex_mix"));
    router.compile();

    auto request = create_request(HTTP_GET, "/data/user123/details/path/to/item.json");
    router.route(mock_session, std::move(request));

    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "complex_mix");
    
    auto user_p = mock_session->_captured_params.get("user");
    ASSERT_TRUE(user_p.has_value());
    ASSERT_EQ(user_p.value(), "user123");

    auto item_p = mock_session->_captured_params.get("itemPath");
    ASSERT_TRUE(item_p.has_value());
    ASSERT_EQ(item_p.value(), "path/to/item.json");
}

// --- Additional Edge Cases and Complex Scenarios ---

TEST_F(RouterMatchTest, NoRoutesDefined) {
    // Router is initialized, but no routes are added.
    router.compile();

    auto request = create_request(HTTP_GET, "/anypath");
    router.route(mock_session, std::move(request));

    ASSERT_FALSE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, VeryLongParameterValue) {
    router.get("/content/:itemId/show", make_verifying_handler("long_param_handler"));
    router.compile();

    std::string long_value(500, 'a');
    long_value += "-";
    for (int i = 0; i < 20; ++i) {
        long_value += "segment" + std::to_string(i) + "_";
    }
    long_value.pop_back(); // Remove last underscore

    auto request = create_request(HTTP_GET, "/content/" + long_value + "/show");
    router.route(mock_session, std::move(request));

    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "long_param_handler");
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    auto param_val = mock_session->_captured_params.get("itemId");
    ASSERT_TRUE(param_val.has_value());
    ASSERT_EQ(std::string(param_val.value()), long_value);
}

TEST_F(RouterMatchTest, VeryLongWildcardCapture) {
    router.get("/assets/*filePath", make_verifying_handler("long_wildcard_handler"));
    router.compile();

    std::string long_path = "a";
    for (int i = 0; i < 50; ++i) { // Create a path like a/b/c/...
        long_path += "/" + std::string(1, static_cast<char>('b' + (i % 24))); // Cycle through b-z
    }
    long_path += "/final_file_with_long_name_and_extension.testdata";

    auto request = create_request(HTTP_GET, "/assets/" + long_path);
    router.route(mock_session, std::move(request));

    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "long_wildcard_handler");
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    auto param_val = mock_session->_captured_params.get("filePath");
    ASSERT_TRUE(param_val.has_value());
    ASSERT_EQ(std::string(param_val.value()), long_path);
}

// --- Path-Route Structural Mismatches ---

TEST_F(RouterMatchTest, PathIsPrefixOfDefinedStaticRoute) {
    router.get("/alpha/beta/gamma", make_verifying_handler("static_abc_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/alpha/beta");
    router.route(mock_session, std::move(request));

    ASSERT_FALSE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, PathIsPrefixOfDefinedParamRoute) {
    router.get("/user/:userId/profile", make_verifying_handler("user_profile_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/user/testuser");
    router.route(mock_session, std::move(request));

    ASSERT_FALSE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, PathIsExtensionOfDefinedStaticRoute) {
    router.get("/data/source", make_verifying_handler("data_source_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/data/source/extra");
    router.route(mock_session, std::move(request));

    ASSERT_FALSE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, PathIsExtensionOfDefinedParamRoute) {
    router.get("/product/:productId", make_verifying_handler("product_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/product/p123/details");
    router.route(mock_session, std::move(request));

    ASSERT_FALSE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, ComplexPriorityMix) {
    router.get("/mix/static_segment/specific_end", make_verifying_handler("H_SS")); // Static-Static
    router.get("/mix/:param_segment/specific_end", make_verifying_handler("H_PS")); // Param-Static
    router.get("/mix/static_segment/:param_end", make_verifying_handler("H_SP"));   // Static-Param
    router.get("/mix/*wildcard_capture", make_verifying_handler("H_WC"));          // Wildcard (changed from H_SW for clarity)
    router.compile();

    // Test 1: Match Static-Static
    mock_session->reset();
    auto req_ss = create_request(HTTP_GET, "/mix/static_segment/specific_end");
    router.route(mock_session, std::move(req_ss));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "H_SS");

    // Test 2: Match Param-Static
    mock_session->reset();
    auto req_ps = create_request(HTTP_GET, "/mix/valueA/specific_end");
    router.route(mock_session, std::move(req_ps));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "H_PS");
    auto param_ps = mock_session->_captured_params.get("param_segment");
    ASSERT_TRUE(param_ps.has_value());
    ASSERT_EQ(param_ps.value(), "valueA");

    // Test 3: Match Static-Param
    mock_session->reset();
    auto req_sp = create_request(HTTP_GET, "/mix/static_segment/valueB");
    router.route(mock_session, std::move(req_sp));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "H_SP");
    auto param_sp = mock_session->_captured_params.get("param_end");
    ASSERT_TRUE(param_sp.has_value());
    ASSERT_EQ(param_sp.value(), "valueB");

    // Test 4: Match Wildcard for a longer, non-matching path
    mock_session->reset();
    auto req_wc_long = create_request(HTTP_GET, "/mix/some/other/path/deep");
    router.route(mock_session, std::move(req_wc_long));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "H_WC");
    auto param_wc_long = mock_session->_captured_params.get("wildcard_capture");
    ASSERT_TRUE(param_wc_long.has_value());
    ASSERT_EQ(param_wc_long.value(), "some/other/path/deep");

    // Test 5: Match Wildcard when path is a prefix of more specific routes but doesn't fully match them
    // e.g. /mix/static_segment -> should be caught by /*wildcard_capture if it's "static_segment"
    // This depends on wildcard behavior for RadixTree (matches empty, matches segments)
    mock_session->reset();
    auto req_wc_prefix_ss = create_request(HTTP_GET, "/mix/static_segment");
    router.route(mock_session, std::move(req_wc_prefix_ss));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "H_WC"); // Assuming wildcard takes precedence if others don't fully match.
    auto param_wc_prefix_ss = mock_session->_captured_params.get("wildcard_capture");
    ASSERT_TRUE(param_wc_prefix_ss.has_value());
    // The RadixTree wildcard matches from the point it's defined.
    // If router is /mix/*wildcard_capture, and path is /mix/static_segment, wildcard_capture is "static_segment".
    ASSERT_EQ(param_wc_prefix_ss.value(), "static_segment");


    // Test 6: Match Wildcard for another prefix case
    mock_session->reset();
    auto req_wc_prefix_ps = create_request(HTTP_GET, "/mix/valueA");
    router.route(mock_session, std::move(req_wc_prefix_ps));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "H_WC");
    auto param_wc_prefix_ps = mock_session->_captured_params.get("wildcard_capture");
    ASSERT_TRUE(param_wc_prefix_ps.has_value());
    ASSERT_EQ(param_wc_prefix_ps.value(), "valueA");
    
    // Test 7: Wildcard should also match if path is just /mix/
    // (assuming /mix/*wildcard where wildcard can be empty)
    mock_session->reset();
    auto req_wc_empty_after_prefix = create_request(HTTP_GET, "/mix/");
    router.route(mock_session, std::move(req_wc_empty_after_prefix));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "H_WC");
    auto param_wc_empty = mock_session->_captured_params.get("wildcard_capture");
    ASSERT_TRUE(param_wc_empty.has_value());
    ASSERT_EQ(param_wc_empty.value(), "");
}

// --- Tests based on "Further tests could include" ---

TEST_F(RouterMatchTest, IdenticalStructureDifferentMethodsParameterized) {
    router.get("/resource/:id", make_verifying_handler("get_resource_id"));
    router.put("/resource/:id", make_verifying_handler("put_resource_id"));
    router.compile();

    // Test GET
    mock_session->reset();
    auto req_get = create_request(HTTP_GET, "/resource/123");
    router.route(mock_session, std::move(req_get));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "get_resource_id");
    auto param_get = mock_session->_captured_params.get("id");
    ASSERT_TRUE(param_get.has_value());
    ASSERT_EQ(param_get.value(), "123");

    // Test PUT
    mock_session->reset();
    auto req_put = create_request(HTTP_PUT, "/resource/456");
    router.route(mock_session, std::move(req_put));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "put_resource_id");
    auto param_put = mock_session->_captured_params.get("id");
    ASSERT_TRUE(param_put.has_value());
    ASSERT_EQ(param_put.value(), "456");

    // Test DELETE (should be 404 or 405, current is 404)
    mock_session->reset();
    auto req_delete = create_request(HTTP_DELETE, "/resource/789");
    router.route(mock_session, std::move(req_delete));
    ASSERT_FALSE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_NOT_FOUND);
}

TEST_F(RouterMatchTest, IdenticalStructureDifferentMethodsWildcard) {
    router.get("/assets/*details", make_verifying_handler("get_assets_details"));
    router.post("/assets/*details", make_verifying_handler("post_assets_details"));
    router.compile();

    // Test GET
    mock_session->reset();
    auto req_get = create_request(HTTP_GET, "/assets/js/app.js");
    router.route(mock_session, std::move(req_get));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "get_assets_details");
    auto param_get = mock_session->_captured_params.get("details");
    ASSERT_TRUE(param_get.has_value());
    ASSERT_EQ(param_get.value(), "js/app.js");

    // Test POST
    mock_session->reset();
    auto req_post = create_request(HTTP_POST, "/assets/css/theme.css");
    router.route(mock_session, std::move(req_post));
    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "post_assets_details");
    auto param_post = mock_session->_captured_params.get("details");
    ASSERT_TRUE(param_post.has_value());
    ASSERT_EQ(param_post.value(), "css/theme.css");
}

TEST_F(RouterMatchTest, ParameterNameWithHyphen) {
    // Test if parameter names like ":item-id" are correctly parsed and matched.
    router.get("/item/:item-id/info", make_verifying_handler("item_hyphen_id_handler"));
    router.compile();

    auto request = create_request(HTTP_GET, "/item/product-abc/info");
    router.route(mock_session, std::move(request));

    ASSERT_TRUE(mock_session->_handler_executed);
    ASSERT_EQ(mock_session->_handler_id, "item_hyphen_id_handler");
    ASSERT_EQ(mock_session->_response.status_code, HTTP_STATUS_OK);
    auto param_val = mock_session->_captured_params.get("item-id");
    ASSERT_TRUE(param_val.has_value());
    ASSERT_EQ(param_val.value(), "product-abc");
}
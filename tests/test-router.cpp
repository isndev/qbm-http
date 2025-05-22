#include <gtest/gtest.h>
#include "../http.h" // Should provide qb::http::Router, Request, Response, Context, PathParameters
                     // qb::http::method, qb::http::status (e.g. HTTP_STATUS_OK), NextMiddlewareFunc
                     // Also qb::uuid, qb::generate_random_uuid, qb::io::uri

#include <string> // For std::string
#include <memory> // For std::shared_ptr
#include <utility> // For std::move
#include <optional> // For std::optional, in case PathParameters::get() uses it and it's not in http.h
#include <stdexcept> // For std::runtime_error

// Mock session for testing
struct MockSession {
    qb::http::Response _response;
    qb::uuid _session_id = qb::generate_random_uuid(); // Assuming qb::generate_random_uuid() is available
    unsigned int _response_write_count = 0;

    qb::http::Response& get_response_ref() {
        return _response;
    }

    MockSession& operator<<(const qb::http::Response& response) {
        _response = response;
        _response_write_count++;
        if (_response_write_count > 1) {
            throw std::runtime_error("MockSession::operator<< called " + 
                                     std::to_string(_response_write_count) + 
                                     " times. Expected no more than 1 call between resets.");
        }
        return *this;
    }
    
    [[nodiscard]] const qb::uuid& id() const {
        return _session_id;
    }

    void reset() {
        _response = qb::http::Response();
        _response_write_count = 0;
    }

    // Verifies the exact number of times operator<< was called.
    // Useful to ensure a response was written (count = 1) or not written (count = 0).
    void verify_response_write_count(unsigned int expected_count = 1) const {
        ASSERT_EQ(_response_write_count, expected_count)
            << "MockSession final response_write_count mismatch. Expected: " << expected_count 
            << ", Actual: " << _response_write_count;
    }
};

// Test fixture for Router tests
class RouterTest : public ::testing::Test {
protected:
    std::shared_ptr<MockSession> mock_session;
    qb::http::Router<MockSession> router; // Assuming Router is in qb::http

    void SetUp() override {
        mock_session = std::make_shared<MockSession>();
        // Router is default constructed
    }

    // Default destructor for gtest compatibility with non-trivial members
    ~RouterTest() override {}

    qb::http::Request create_request(qb::http::method method_val, const std::string& target_path) {
        qb::http::Request req; // Default constructor
        req.method() = method_val;
        req.uri() = qb::io::uri(target_path); // Construct URI from path
        req.major_version = 1;
        req.minor_version = 1; // HTTP/1.1
        // Add any other necessary fields if your Request requires them, e.g. headers
        return req;
    }
};

TEST_F(RouterTest, RouterInitialization) {
    ASSERT_NO_THROW(qb::http::Router<MockSession> test_router);
}

TEST_F(RouterTest, AddAndMatchSimpleGetRoute) {
    router.get("/hello", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "world";
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_GET, "/hello");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "world");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, RouteNotFound) {
    router.get("/someotherpath", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_GET, "/nonexistent");
    router.route(mock_session, std::move(request));
    
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, AddRouteWithParametersAndMatch) {
    router.get("/users/:id/profile", [](auto ctx) {
        auto id_param = ctx->path_param("id");
        // Fallback if path_param throws or returns an empty optional/string on not found.
        // Assuming path_param returns string directly, and RadixTree ensures it exists if matched.
        // If path_param could return an empty string for a missing (but matched) param:
        // if (id_param.empty()) { id_param = "not_found_safeguard"; }

        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "User ID: " + id_param;
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_GET, "/users/123/profile");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "User ID: 123");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, RouteWithMiddleware) {
    router.use([](auto ctx, auto next) {
        ctx->response().set_header("X-Middleware-Applied", "true");
        next();
    }, "GlobalMiddleware");

    router.get("/protected", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Protected content";
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_GET, "/protected");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_TRUE(mock_session->_response.has_header("X-Middleware-Applied"));
    ASSERT_EQ(mock_session->_response.header("X-Middleware-Applied", 0, ""), "true");
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Protected content");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, WildcardRouteSimple) {
    router.get("/files/*filepath", [](auto ctx) {
        auto fp = ctx->path_param("filepath");
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "File: " + fp;
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_GET, "/files/documents/report.pdf");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "File: documents/report.pdf");
    mock_session->verify_response_write_count();

    mock_session->reset(); // Reset for next call
    auto request2 = create_request(HTTP_GET, "/files/image.png");
    router.route(mock_session, std::move(request2));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "File: image.png");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, StaticRoutePriorityOverWildcard) {
    // Define static route
    router.get("/data/specific", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Static specific data";
        ctx->complete();
    });

    // Define wildcard route with same prefix
    router.get("/data/*whatever", [](auto ctx) {
        auto what = ctx->path_param("whatever");
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Wildcard data: " + what;
        ctx->complete();
    });

    router.compile();

    // Request the specific static path
    auto request_static = create_request(HTTP_GET, "/data/specific");
    router.route(mock_session, std::move(request_static));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Static specific data");
    mock_session->verify_response_write_count();

    mock_session->reset(); // Reset for next call
    // Request a path that should match the wildcard
    auto request_wildcard = create_request(HTTP_GET, "/data/general/info");
    router.route(mock_session, std::move(request_wildcard));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Wildcard data: general/info");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, ParameterRoutePriorityOverWildcard) {
    // Define parameterized route
    router.get("/api/:version/info", [](auto ctx) {
        auto version = ctx->path_param("version");
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "API Info Version: " + version;
        ctx->complete();
    });

    // Define wildcard route with same prefix
    router.get("/api/*path", [](auto ctx) {
        auto p_val = ctx->path_param("path");
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "API Wildcard Path: " + p_val;
        ctx->complete();
    });

    router.compile();

    // Request a path that should match the parameterized route
    auto request_param = create_request(HTTP_GET, "/api/v2/info");
    router.route(mock_session, std::move(request_param));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "API Info Version: v2");
    mock_session->verify_response_write_count();

    mock_session->reset(); // Reset for next call
    // Request a path that should fall through to the wildcard
    auto request_wildcard = create_request(HTTP_GET, "/api/v1/status/all");
    router.route(mock_session, std::move(request_wildcard));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "API Wildcard Path: v1/status/all");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, PostRouteSimple) {
    router.post("/create", [](auto ctx) {
        ctx->response().status() = qb::http::status::CREATED; // 201
        ctx->response().body() = "Resource created";
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_POST, "/create");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_CREATED);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Resource created");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, RouteOverwriting) {
    router.get("/overwrite", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "First definition";
        ctx->complete();
    });

    // Overwrite with a new handler for the same path and method
    router.get("/overwrite", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Second definition takes precedence";
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_GET, "/overwrite");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Second definition takes precedence");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, TrailingSlashEquivalence) {
    // Define route without trailing slash
    router.get("/path", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Path matched";
        ctx->complete();
    });

    router.compile();

    // Request with trailing slash
    auto request_with_slash = create_request(HTTP_GET, "/path/");
    router.route(mock_session, std::move(request_with_slash));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Path matched");
    mock_session->verify_response_write_count();

    mock_session->reset(); // Reset for next call

    // Request without trailing slash
    auto request_without_slash = create_request(HTTP_GET, "/path");
    router.route(mock_session, std::move(request_without_slash));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Path matched");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, RootPath) {
    router.get("/", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Root path matched";
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_GET, "/");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Root path matched");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, PathCaseSensitivity) {
    router.get("/casepath", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Correct case";
        ctx->complete();
    });

    router.compile();

    // Request with correct case
    auto request_correct_case = create_request(HTTP_GET, "/casepath");
    router.route(mock_session, std::move(request_correct_case));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Correct case");
    mock_session->verify_response_write_count();

    mock_session->reset(); // Reset for next call

    // Request with incorrect case - should result in 404 Not Found
    auto request_incorrect_case = create_request(HTTP_GET, "/CasePath");
    router.route(mock_session, std::move(request_incorrect_case));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, MultipleMiddleware) {
    // First middleware, adds header one
    router.use([](auto ctx, auto next) {
        ctx->response().add_header("X-Middleware-One", "AppliedOne");
        next();
    }, "MiddlewareOne");

    // Second middleware, adds header two
    router.use([](auto ctx, auto next) {
        ctx->response().add_header("X-Middleware-Two", "AppliedTwo");
        next();
    }, "MiddlewareTwo");

    router.get("/multi-mw", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Multi-middleware content";
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_GET, "/multi-mw");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_TRUE(mock_session->_response.has_header("X-Middleware-One"));
    ASSERT_EQ(mock_session->_response.header("X-Middleware-One", 0, ""), "AppliedOne");
    ASSERT_TRUE(mock_session->_response.has_header("X-Middleware-Two"));
    ASSERT_EQ(mock_session->_response.header("X-Middleware-Two", 0, ""), "AppliedTwo");
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Multi-middleware content");
    mock_session->verify_response_write_count();

    // Verify order by checking header presence - this is a bit indirect for order,
    // but if one was missing, it might indicate an issue. True order check would require
    // side effects like pushing to a vector in the context.
}

TEST_F(RouterTest, AddAndMatchSimplePutRoute) {
    router.put("/resource/123", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Resource 123 updated";
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_PUT, "/resource/123");
    // Optionally add request body for PUT if your Request object supports it easily
    // request.body() = "put data"; 
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Resource 123 updated");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, AddAndMatchSimpleDeleteRoute) {
    router.del("/resource/456", [](auto ctx) { // Assuming .del() or .delete_()
        ctx->response().status() = qb::http::status::NO_CONTENT; // 204 No Content is common
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_DELETE, "/resource/456");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_NO_CONTENT);
    ASSERT_TRUE(mock_session->_response.body().raw().empty()); // No body for 204
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, AddAndMatchSimplePatchRoute) {
    router.patch("/resource/789", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Resource 789 patched";
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_PATCH, "/resource/789");
    // Optionally add request body for PATCH
    // request.body() = "patch data";
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Resource 789 patched");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, AddAndMatchSimpleHeadRoute) {
    // Define a GET route that sets a header
    router.get("/info", [](auto ctx) {
        ctx->response().set_header("X-Info-Detail", "SomeDetail");
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "This is info"; // Body for GET
        ctx->complete();
    });

    // Define a HEAD route that should mimic GET's headers but no body
    router.head("/info", [](auto ctx) {
        // In a real scenario, the router might automatically handle HEAD from GET,
        // or the handler would need to know to set headers but not body.
        // For this test, we explicitly set the header and no body.
        ctx->response().set_header("X-Info-Detail", "SomeDetail");
        ctx->response().status() = qb::http::status::OK;
        // No body for HEAD
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_HEAD, "/info");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_TRUE(mock_session->_response.has_header("X-Info-Detail"));
    ASSERT_EQ(mock_session->_response.header("X-Info-Detail", 0, ""), "SomeDetail");
    ASSERT_TRUE(mock_session->_response.body().raw().empty()); // Crucial for HEAD
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, AddAndMatchSimpleOptionsRoute) {
    router.options("/options-check", [](auto ctx) {
        ctx->response().set_header("Allow", "GET, POST, OPTIONS"); // Example
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_OPTIONS, "/options-check");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_TRUE(mock_session->_response.has_header("Allow"));
    ASSERT_EQ(mock_session->_response.header("Allow", 0, ""), "GET, POST, OPTIONS");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, MiddlewareModifyingRequest) {
    router.use([](auto ctx, auto next) {
        ctx->set("middleware_flag", true);
        next();
    }, "FlagSettingMiddleware");

    router.get("/check-flag", [](auto ctx) {
        bool flag_found = false;
        auto flag_opt = ctx->template get<bool>("middleware_flag");
        if (flag_opt.has_value()) {
            flag_found = flag_opt.value();
        }

        if (flag_found) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "Flag was set";
        } else {
            ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
            ctx->response().body() = "Flag not set or wrong type";
        }
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_GET, "/check-flag");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Flag was set");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, MiddlewareShortCircuitingResponse) {
    router.use([](auto ctx, auto next) {
        ctx->response().status() = qb::http::status::UNAUTHORIZED;
        ctx->response().body() = "Access denied by middleware";
        ctx->response().set_header("X-ShortCircuit", "true");
        ctx->complete(); // Middleware completes the response, `next` should not be called by RouterCore
        // next(); // Should not be called if response is sent
    }, "AuthMiddleware");

    // This route handler should ideally not be called.
    router.get("/secret-data", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "This should not be seen";
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_GET, "/secret-data");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_UNAUTHORIZED);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Access denied by middleware");
    ASSERT_TRUE(mock_session->_response.has_header("X-ShortCircuit"));
    mock_session->verify_response_write_count(1); // Ensure the main handler didn't also try to write.
}

TEST_F(RouterTest, RouteSpecificMiddleware) {
    auto group = router.group("/api");
    group->use([](auto ctx, auto next) {
        ctx->response().add_header("X-Api-Group", "true");
        next();
    }, "ApiGroupMiddleware");

    group->get("/status", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "API Status OK";
        ctx->complete();
    });

    router.get("/non-api/status", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Non-API Status OK";
        ctx->complete();
    });

    router.compile();

    // Test endpoint within the group
    auto api_request = create_request(HTTP_GET, "/api/status");
    router.route(mock_session, std::move(api_request));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_TRUE(mock_session->_response.has_header("X-Api-Group"));
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "API Status OK");
    mock_session->verify_response_write_count();

    mock_session->reset();

    // Test endpoint outside the group
    auto non_api_request = create_request(HTTP_GET, "/non-api/status");
    router.route(mock_session, std::move(non_api_request));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_FALSE(mock_session->_response.has_header("X-Api-Group"));
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Non-API Status OK");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, RouteWithMultipleParameters) {
    router.get("/users/:userId/items/:itemId", [](auto ctx) {
        auto user_id = ctx->path_param("userId");
        auto item_id = ctx->path_param("itemId");
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "User: " + user_id + ", Item: " + item_id;
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_GET, "/users/u42/items/i99");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "User: u42, Item: i99");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, ParameterAtEndOfPath) {
    router.get("/content/:pageId", [](auto ctx) {
        auto page_id = ctx->path_param("pageId");
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Page: " + page_id;
        ctx->complete();
    });

    router.compile();

    auto request = create_request(HTTP_GET, "/content/about-us");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Page: about-us");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, RouteWithEmptyParameterValue) {
    router.get("/files/:filename/details", [](auto ctx) {
        auto filename = ctx->path_param("filename");
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "File: " + filename;
        ctx->complete();
    });

    router.compile();

    // Request path like /files//details - how RadixTree handles empty segments for params
    // Assuming it might not match or treat param as empty. 
    // Current RadixTree split_path_to_segments might already filter out empty segments from `//`.
    // If it filters them, then "/files//details" becomes {"files", "details"} and won't match /files/:filename/details.
    // Test for 404 first. If it should match with empty param, this test needs adjustment.
    auto request = create_request(HTTP_GET, "/files//details");
    router.route(mock_session, std::move(request));

    // This assertion depends on RadixTree behavior for "//" in path when a param is expected.
    // If "//" causes the segment to be skipped, it won't match the :filename param -> 404.
    // If it matches with filename="", then status would be OK.
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_NOT_FOUND);
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, WildcardAtRoot) {
    router.get("/*filepath", [](auto ctx) {
        auto fp = ctx->path_param("filepath");
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Root wildcard: " + fp;
        ctx->complete();
    });

    router.compile();

    auto request1 = create_request(HTTP_GET, "/some/path.html");
    router.route(mock_session, std::move(request1));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Root wildcard: some/path.html");
    mock_session->verify_response_write_count();

    mock_session->reset();
    auto request2 = create_request(HTTP_GET, "/another.txt");
    router.route(mock_session, std::move(request2));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Root wildcard: another.txt");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, WildcardConsumingNothing) {
    // Route where wildcard is at the end, after a slash
    router.get("/archive/*subpath", [](auto ctx) {
        auto sp = ctx->path_param("subpath");
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Archive subpath: [" + sp + "]"; // Brackets to see if empty
        ctx->complete();
    });

    router.compile();

    // Request path is exactly the prefix before wildcard, with a trailing slash
    // RadixTree's split_path_to_segments for "/archive/" might result in {"archive"}
    // If so, matching "/archive/*subpath" would make subpath empty.
    auto request = create_request(HTTP_GET, "/archive/");
    router.route(mock_session, std::move(request));

    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Archive subpath: []");
    mock_session->verify_response_write_count();

    mock_session->reset();
    // Request path without trailing slash, should also result in empty subpath if that's the design
    auto request_no_slash = create_request(HTTP_GET, "/archive");
    router.route(mock_session, std::move(request_no_slash));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Archive subpath: []");
    mock_session->verify_response_write_count();
}

TEST_F(RouterTest, AddRouteWithDuplicateParameterNameInSameSegment) {
    // This test checks if the router (specifically the RadixTree) prevents adding
    // routes with conflicting parameter definitions that are ambiguous during compile.
    // e.g. /:id/:id or /:name/*name
    // The exact exception type might vary based on RadixTree implementation.

    router.get("/test/:id/:id", [](auto ctx) {
        // This handler should not be reached if the definition throws.
        ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
        ctx->response().body() = "Handler reached for invalid route /test/:id/:id";
        ctx->complete();
    });

    ASSERT_THROW(
        router.compile(), // Exception expected during compilation of routes
        std::invalid_argument 
    );

    // Reset router state for the next part of the test, as compile() might have partially modified it or cleared it.
    // A robust way is to use a new router instance or ensure a full clear.
    // For simplicity here, we assume the router might be in an undefined state after a throwing compile,
    // or that compile() clears before attempting.
    // Let's re-initialize the router to be safe for the next part of this test case.
    router = qb::http::Router<MockSession>(); // Re-initialize

    // Also test conflicting param and wildcard names
    router.get("/other/:name/*name", [](auto ctx) {
        ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
        ctx->response().body() = "Handler reached for invalid route /other/:name/*name";
        ctx->complete();
    });
    ASSERT_THROW(
        router.compile(), // Exception expected during compilation
        std::invalid_argument
    );

    // Re-initialize router again before testing a valid route.
    router = qb::http::Router<MockSession>(); 

    // Ensure a valid route can still be added and matched after attempted invalid ones,
    // meaning the router's internal state wasn't corrupted or was reset.
    router.get("/good/route", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Good route ok";
        ctx->complete();
    });

    // This compile should not throw
    ASSERT_NO_THROW(router.compile());

    auto request = create_request(HTTP_GET, "/good/route");
    router.route(mock_session, std::move(request));
    ASSERT_EQ(mock_session->_response.status(), HTTP_STATUS_OK);
    ASSERT_EQ(mock_session->_response.body().as<std::string>(), "Good route ok");
    mock_session->verify_response_write_count();
} 
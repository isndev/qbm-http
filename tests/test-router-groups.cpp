#include <gtest/gtest.h>
#include "../http.h"

// Mock session for testing
struct MockSession {
    qb::http::Response &
    response() {
        return _response;
    }
    qb::http::Response _response;
    qb::uuid _session_id = qb::generate_random_uuid();

    MockSession &
    operator<<(qb::http::Response const &response) {
        _response = std::move(qb::http::Response(response));
        return *this;
    }
    
    // Return the session ID
    [[nodiscard]] const qb::uuid& id() const {
        return _session_id;
    }
    
    // Method to check if the session is connected - always returns true in tests
    [[nodiscard]] bool is_connected() const {
        return true;
    }
    
    // Callback function when session is disconnected
    void set_disconnect_callback(std::function<void(qb::uuid)> callback) {
        // Store but don't use in tests
    }
};

// Test types
using TestRequest = qb::http::TRequest<std::string>;
using TestRouter  = TestRequest::Router<MockSession>;
using Context     = TestRouter::Context;

class RouterGroupTest : public ::testing::Test {
protected:
    std::unique_ptr<TestRouter> router;
    std::shared_ptr<MockSession> session;

    void
    SetUp() override {
        session = std::make_shared<MockSession>();
        router = std::make_unique<TestRouter>();
    }
};

// Test basic route groups
TEST_F(RouterGroupTest, BasicRouteGroups) {
    bool route1_called = false;
    bool route2_called = false;
    
    // Create a route group
    auto& group = router->group("/api");
    
    // Add routes to the group
    group.get("/users", [&](Context& ctx) {
        route1_called = true;
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Users list";
    });
    
    group.post("/users", [&](Context& ctx) {
        route2_called = true;
        ctx.response.status_code = HTTP_STATUS_CREATED;
        ctx.response.body() = "User created";
    });
    
    // Test GET route
    TestRequest req;
    req.method = HTTP_GET;
    req._uri = qb::io::uri("/api/users");
    EXPECT_TRUE(router->route(session, req));
    EXPECT_TRUE(route1_called);
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(session->_response.body().as<std::string>(), "Users list");
    
    // Test POST route
    session->_response = qb::http::Response();
    req.method = HTTP_POST;
    EXPECT_TRUE(router->route(session, req));
    EXPECT_TRUE(route2_called);
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_CREATED);
    EXPECT_EQ(session->_response.body().as<std::string>(), "User created");
}

// Test creating multiple groups in sequence
TEST_F(RouterGroupTest, MultipleGroupsSequence) {
    // Create multiple groups in sequence - this used to cause segfaults
    auto& group1 = router->group("/api/v1");
    auto& group2 = router->group("/api/v2");
    
    // Add routes to both groups
    group1.get("/status", [](Context& ctx) {
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "API v1 Status: OK";
    });
    
    group2.get("/status", [](Context& ctx) {
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "API v2 Status: OK";
    });
    
    // Test group 1 route
    TestRequest req;
    req.method = HTTP_GET;
    req._uri = qb::io::uri("/api/v1/status");
    EXPECT_TRUE(router->route(session, req));
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(session->_response.body().as<std::string>(), "API v1 Status: OK");
    
    // Test group 2 route
    session->_response = qb::http::Response();
    req._uri = qb::io::uri("/api/v2/status");
    EXPECT_TRUE(router->route(session, req));
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(session->_response.body().as<std::string>(), "API v2 Status: OK");
}

// Test nested route groups (2 levels)
TEST_F(RouterGroupTest, NestedRouteGroups) {
    // Create a parent group
    auto& parent_group = router->group("/api");
    
    // Create a nested group using the parent group
    auto& nested_group = parent_group.group("/v1");
    
    // Add routes to the nested group
    nested_group.get("/users", [](Context& ctx) {
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "API v1 Users";
    });
    
    // Test the nested route
    TestRequest req;
    req.method = HTTP_GET;
    req._uri = qb::io::uri("/api/v1/users");
    EXPECT_TRUE(router->route(session, req));
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(session->_response.body().as<std::string>(), "API v1 Users");
}

// Test deeply nested route groups (3+ levels)
TEST_F(RouterGroupTest, DeeplyNestedRouteGroups) {
    // Create a multi-level nested structure
    auto& level1 = router->group("/api");
    auto& level2 = level1.group("/v1");
    auto& level3 = level2.group("/services");
    auto& level4 = level3.group("/auth");
    
    // Add route to the deepest level
    level4.post("/login", [](Context& ctx) {
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Login successful";
    });
    
    // Test the deeply nested route
    TestRequest req;
    req.method = HTTP_POST;
    req._uri = qb::io::uri("/api/v1/services/auth/login");
    EXPECT_TRUE(router->route(session, req));
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(session->_response.body().as<std::string>(), "Login successful");
}

// Test group route parameter extraction
TEST_F(RouterGroupTest, GroupRouteParameters) {
    auto& group = router->group("/api");
    
    group.get("/users/:id", [](Context& ctx) {
        std::string id = ctx.param("id");
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "User ID: " + id;
    });
    
    TestRequest req;
    req.method = HTTP_GET;
    req._uri = qb::io::uri("/api/users/123");
    EXPECT_TRUE(router->route(session, req));
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(session->_response.body().as<std::string>(), "User ID: 123");
}

// Test nested controllers with groups
TEST_F(RouterGroupTest, NestedControllersWithGroups) {
    // Define a controller with internal groups
    class UserController : public TestRouter::Controller {
    public:
        UserController() : TestRouter::Controller("/users") {
            // Base routes
            router().get("/", [](Context& ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "List of users";
            });
            
            router().get("/:id", [](Context& ctx) {
                auto id = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "User details: " + id;
            });
            
            // Create a nested group for profile operations
            auto& profile_group = router().group("/profile");
            
            profile_group.get("/:id", [](Context& ctx) {
                auto id = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "User profile: " + id;
            });
            
            profile_group.put("/:id", [](Context& ctx) {
                auto id = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "Updated profile: " + id;
            });
            
            // Create another nested group for settings
            auto& settings_group = router().group("/settings");
            
            settings_group.get("/:id", [](Context& ctx) {
                auto id = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "User settings: " + id;
            });
        }
    };
    
    // Register the controller
    router->controller<UserController>();
    
    // Test base routes
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/users");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "List of users");
    }
    
    // Test user detail route
    {
        session->_response = qb::http::Response();
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/users/123");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "User details: 123");
    }
    
    // Test profile group route
    {
        session->_response = qb::http::Response();
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/users/profile/456");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "User profile: 456");
    }
    
    // Test settings group route
    {
        session->_response = qb::http::Response();
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/users/settings/789");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "User settings: 789");
    }
}

// Test group middleware application
TEST_F(RouterGroupTest, GroupMiddleware) {
    bool route_called = false;
    
    // Create a route group
    auto& group = router->group("/api");
    
    // Add a route to the group with a closure capturing our flag
    group.get("/test", [&route_called](Context& ctx) {
        route_called = true;
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Test response";
    });
    
    // Test the route
    TestRequest req;
    req.method = HTTP_GET;
    req._uri = qb::io::uri("/api/test");
    EXPECT_TRUE(router->route(session, req));
    EXPECT_TRUE(route_called);
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(session->_response.body().as<std::string>(), "Test response");
}

// Test very complex nested structure (extreme case)
TEST_F(RouterGroupTest, ComplexNestedStructure) {
    // Create a complex structure with multiple nested levels and branches
    auto& api = router->group("/api");
    
    // Branch 1: Version 1 API
    auto& v1 = api.group("/v1");
    auto& v1_users = v1.group("/users");
    auto& v1_posts = v1.group("/posts");
    
    // Branch 2: Version 2 API
    auto& v2 = api.group("/v2");
    auto& v2_users = v2.group("/users");
    auto& v2_posts = v2.group("/posts");
    
    // Branch 3: Admin API
    auto& admin = api.group("/admin");
    auto& admin_users = admin.group("/users");
    auto& admin_settings = admin.group("/settings");
    
    // Branch 4: Super deep nesting
    auto& deep = api.group("/deep");
    auto& deep_level1 = deep.group("/level1");
    auto& deep_level2 = deep_level1.group("/level2");
    auto& deep_level3 = deep_level2.group("/level3");
    auto& deep_level4 = deep_level3.group("/level4");
    auto& deep_level5 = deep_level4.group("/level5");
    
    // Add routes to the deepest levels
    v1_users.get("/:id", [](Context& ctx) {
        auto id = ctx.param("id");
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "V1 User: " + id;
    });
    
    v2_users.get("/:id", [](Context& ctx) {
        auto id = ctx.param("id");
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "V2 User: " + id;
    });
    
    admin_settings.get("/global", [](Context& ctx) {
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Global Settings";
    });
    
    deep_level5.get("/endpoint", [](Context& ctx) {
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Deep Endpoint Reached";
    });
    
    // Test routes on different branches
    
    // Test v1 users
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/api/v1/users/123");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "V1 User: 123");
    }
    
    // Test v2 users
    {
        session->_response = qb::http::Response();
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/api/v2/users/456");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "V2 User: 456");
    }
    
    // Test admin settings
    {
        session->_response = qb::http::Response();
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/api/admin/settings/global");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Global Settings");
    }
    
    // Test deep endpoint
    {
        session->_response = qb::http::Response();
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/api/deep/level1/level2/level3/level4/level5/endpoint");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Deep Endpoint Reached");
    }
}

// Test sequential group creation with modification (potential source of bugs)
TEST_F(RouterGroupTest, SequentialGroupCreationWithModification) {
    // Create several groups and then modify them
    auto& group1 = router->group("/group1");
    auto& group2 = router->group("/group2");
    auto& group3 = router->group("/group3");
    
    // Now go back and add routes to each group
    group1.get("/endpoint", [](Context& ctx) {
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Group 1 Endpoint";
    });
    
    group2.get("/endpoint", [](Context& ctx) {
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Group 2 Endpoint";
    });
    
    group3.get("/endpoint", [](Context& ctx) {
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Group 3 Endpoint";
    });
    
    // Test each group's route
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/group1/endpoint");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Group 1 Endpoint");
    }
    
    {
        session->_response = qb::http::Response();
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/group2/endpoint");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Group 2 Endpoint");
    }
    
    {
        session->_response = qb::http::Response();
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/group3/endpoint");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Group 3 Endpoint");
    }
}

// Test OpenAPI tag propagation in nested groups
TEST_F(RouterGroupTest, OpenAPITagPropagation) {
    // Create nested groups with tags
    auto& api = router->group("/api");
    api.withTag("API");
    
    auto& v1 = api.group("/v1");
    v1.withTag("v1");
    
    auto& users = v1.group("/users");
    users.withTag("Users");
    
    // Add routes to the deeply nested group
    users.get("/", [](Context& ctx) {
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "List of Users";
    });
    
    users.get("/:id", [](Context& ctx) {
        auto id = ctx.param("id");
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "User: " + id;
    });
    
    // Test route to ensure it works normally
    TestRequest req;
    req.method = HTTP_GET;
    req._uri = qb::io::uri("/api/v1/users/123");
    EXPECT_TRUE(router->route(session, req));
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(session->_response.body().as<std::string>(), "User: 123");
    
    // Test tag propagation by inspecting the router's groups
    auto groups = router->getGroups();
    ASSERT_FALSE(groups.empty());
    
    // Find our groups by prefix and verify tags
    for (auto* group : groups) {
        if (group->getPrefix() == "/api") {
            const auto& metadata = group->getMetadata();
            ASSERT_FALSE(metadata.tags.empty());
            EXPECT_TRUE(std::find(metadata.tags.begin(), metadata.tags.end(), "API") != metadata.tags.end());
        }
        else if (group->getPrefix() == "/api/v1") {
            const auto& metadata = group->getMetadata();
            ASSERT_FALSE(metadata.tags.empty());
            EXPECT_TRUE(std::find(metadata.tags.begin(), metadata.tags.end(), "v1") != metadata.tags.end());
        }
        else if (group->getPrefix() == "/api/v1/users") {
            const auto& metadata = group->getMetadata();
            ASSERT_FALSE(metadata.tags.empty());
            EXPECT_TRUE(std::find(metadata.tags.begin(), metadata.tags.end(), "Users") != metadata.tags.end());
        }
    }
}

// Test mixture of route groups and controllers with sharing and borrowing references
TEST_F(RouterGroupTest, MixedGroupsAndControllers) {
    // Define a complex controller with internal groups
    class ComplexController : public TestRouter::Controller {
    public:
        ComplexController() : TestRouter::Controller("/complex") {
            // Base routes
            router().get("/", [](Context& ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "Complex Controller Root";
            });
            
            // Create internal groups
            auto& data_group = router().group("/data");
            auto& config_group = router().group("/config");
            
            // Add routes to the groups
            data_group.get("/stats", [](Context& ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "Complex Data Stats";
            });
            
            config_group.get("/settings", [](Context& ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "Complex Config Settings";
            });
            
            // Create deeply nested groups
            auto& nested = data_group.group("/nested");
            nested.get("/deep", [](Context& ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "Complex Nested Deep Data";
            });
        }
    };
    
    // Create external groups
    auto& api = router->group("/api");
    auto& v1 = api.group("/v1");
    
    // Register controller under the v1 group prefix path
    router->controller<ComplexController>();
    
    // Create more groups after controller registration
    auto& admin = api.group("/admin");
    admin.get("/dashboard", [](Context& ctx) {
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Admin Dashboard";
    });
    
    // Test the complex structure
    
    // Test controller root
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/complex");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Complex Controller Root");
    }
    
    // Test controller internal group
    {
        session->_response = qb::http::Response();
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/complex/data/stats");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Complex Data Stats");
    }
    
    // Test controller deeply nested group
    {
        session->_response = qb::http::Response();
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/complex/data/nested/deep");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Complex Nested Deep Data");
    }
    
    // Test the admin group (created after controller)
    {
        session->_response = qb::http::Response();
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/api/admin/dashboard");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Admin Dashboard");
    }
}

int
main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
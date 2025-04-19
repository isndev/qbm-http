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
    [[nodiscard]] const qb::uuid& id() const { // Ensure const reference return type
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

class RouterTest : public ::testing::Test {
protected:
    std::unique_ptr<TestRouter> router;
    std::shared_ptr<MockSession> session; // Use shared_ptr for session

    void
    SetUp() override {
        session = std::make_shared<MockSession>(); // Create session using make_shared
        router = std::make_unique<TestRouter>();
    }
};

// Test basic routing with different HTTP methods
TEST_F(RouterTest, BasicRouting) {
    bool get_called  = false;
    bool post_called = false;
    bool put_called  = false;
    bool del_called  = false;

    // Register routes using lambda functions
    router->get("/test", [&](Context &ctx) {
        get_called               = true;
        ctx.response.status_code = HTTP_STATUS_OK;
    });

    router->post("/test", [&](Context &ctx) {
        post_called              = true;
        ctx.response.status_code = HTTP_STATUS_CREATED;
    });

    router->put("/test", [&](Context &ctx) {
        put_called               = true;
        ctx.response.status_code = HTTP_STATUS_OK;
    });

    router->del("/test", [&](Context &ctx) {
        del_called               = true;
        ctx.response.status_code = HTTP_STATUS_NO_CONTENT;
    });

    // Test get
    TestRequest req;
    req.method = HTTP_GET;
    req._uri   = qb::io::uri("/test");
    EXPECT_TRUE(router->route(session, req)); // Pass shared_ptr directly
    EXPECT_TRUE(get_called);
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);

    // Test post
    req.method = HTTP_POST;
    EXPECT_TRUE(router->route(session, req)); // Pass shared_ptr directly
    EXPECT_TRUE(post_called);
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_CREATED);

    // Test PUT
    req.method = HTTP_PUT;
    EXPECT_TRUE(router->route(session, req)); // Pass shared_ptr directly
    EXPECT_TRUE(put_called);
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);

    // Test DELETE
    req.method = HTTP_DELETE;
    EXPECT_TRUE(router->route(session, req)); // Pass shared_ptr directly
    EXPECT_TRUE(del_called);
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_NO_CONTENT);
}

// Test route parameters
TEST_F(RouterTest, RouteParameters) {
    std::string user_id;
    std::string post_id;

    router->get("/users/:id/posts/:post_id", [&](Context &ctx) {
        user_id                  = ctx.param("id");
        post_id                  = ctx.param("post_id");
        ctx.response.status_code = HTTP_STATUS_OK;
    });

    TestRequest req;
    req.method = HTTP_GET;
    req._uri   = qb::io::uri("/users/123/posts/456");
    EXPECT_TRUE(router->route(session, req)); // Pass shared_ptr directly
    EXPECT_EQ(user_id, "123");
    EXPECT_EQ(post_id, "456");
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
}

// Test controller
TEST_F(RouterTest, Controller) {
    class UserController : public TestRouter::Controller {
    public:
        UserController()
            : TestRouter::Controller("/users") {
            router().get("/", [](TestRouter::Context &ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body()      = "List of users";
            });

            router().get("/:id", [](TestRouter::Context &ctx) {
                auto id                  = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body()      = "User details for ID: " + id;
            });
        }
    };

    router->controller<UserController>();

    // Test list users
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri   = qb::io::uri("/users");
        EXPECT_TRUE(router->route(session, req)); // Pass shared_ptr directly
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "List of users");
    }

    // Test get user by id
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri   = qb::io::uri("/users/123");
        EXPECT_TRUE(router->route(session, req)); // Pass shared_ptr directly
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(),
                  "User details for ID: 123");
    }
}

// Test custom route class
TEST_F(RouterTest, CustomRoute) {
    struct CustomRoute : public TestRouter::Route {
        CustomRoute()
            : TestRouter::Route("/custom") {}

        void
        process(Context &ctx) override {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body()      = "Custom route response";
        }
    };

    router->get<CustomRoute>();

    TestRequest req;
    req.method = HTTP_GET;
    req._uri   = qb::io::uri("/custom");
    EXPECT_TRUE(router->route(session, req)); // Pass shared_ptr directly
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(session->_response.body().as<std::string>(), "Custom route response");
}

// Test nested controllers
TEST_F(RouterTest, NestedControllers) {
    class ProductController : public TestRouter::Controller {
    public:
        ProductController()
            : TestRouter::Controller("/products") {
            router().get("/", [](TestRouter::Context &ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body()      = "List of products";
            });

            router().get("/:id", [](TestRouter::Context &ctx) {
                auto id                  = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body()      = "Product details for ID: " + id;
            });
        }

        // Constructor with a route prefix for nesting
        explicit ProductController(const std::string &prefix)
            : TestRouter::Controller(prefix + "/products") {
            router().get("/", [](TestRouter::Context &ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body()      = "List of products";
            });

            router().get("/:id", [](TestRouter::Context &ctx) {
                auto id                  = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body()      = "Product details for ID: " + id;
            });
        }
    };

    class CategoryController : public TestRouter::Controller {
    public:
        CategoryController()
            : TestRouter::Controller("/categories") {
            router().get("/", [](TestRouter::Context &ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body()      = "List of categories";
            });

            router().get("/:id", [](TestRouter::Context &ctx) {
                auto id                  = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body()      = "Category details for ID: " + id;
            });

            // Add products under a specific category
            router().get("/:category_id/products", [](TestRouter::Context &ctx) {
                auto category_id         = ctx.param("category_id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body()      = "Products in category: " + category_id;
            });

            router().get("/:category_id/products/:id", [](TestRouter::Context &ctx) {
                auto category_id         = ctx.param("category_id");
                auto id                  = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() =
                    "Product ID: " + id + " in category: " + category_id;
            });
        }
    };

    router->controller<CategoryController>();
    router->controller<ProductController>();

    // Test list categories
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri   = qb::io::uri("/categories");
        EXPECT_TRUE(router->route(session, req)); // Pass shared_ptr directly
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "List of categories");
    }

    // Test get category by id
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri   = qb::io::uri("/categories/electronics");
        EXPECT_TRUE(router->route(session, req)); // Pass shared_ptr directly
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(),
                  "Category details for ID: electronics");
    }

    // Test list products in a category
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri   = qb::io::uri("/categories/electronics/products");
        EXPECT_TRUE(router->route(session, req)); // Pass shared_ptr directly
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(),
                  "Products in category: electronics");
    }

    // Test get product by id in a category
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri   = qb::io::uri("/categories/electronics/products/123");
        EXPECT_TRUE(router->route(session, req)); // Pass shared_ptr directly
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(),
                  "Product ID: 123 in category: electronics");
    }

    // Test normal products endpoint
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri   = qb::io::uri("/products/456");
        EXPECT_TRUE(router->route(session, req)); // Pass shared_ptr directly
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(),
                  "Product details for ID: 456");
    }
}

// Test multiple levels of nested controllers
TEST_F(RouterTest, MultiLevelNestedControllers) {
    // Route de niveau 1 - Magasin
    router->get("/stores/:store_id", [](Context &ctx) {
        std::string store_id     = ctx.param("store_id");
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body()      = "Store: " + store_id;
    });

    // Route de niveau 2 - Produit dans un magasin
    router->get("/stores/:store_id/products/:product_id", [](Context &ctx) {
        std::string store_id     = ctx.param("store_id");
        std::string product_id   = ctx.param("product_id");
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body()      = "Product: " + product_id + " in store: " + store_id;
    });

    // Route de niveau 3 - Avis sur un produit dans un magasin
    router->get("/stores/:store_id/products/:product_id/reviews/:review_id",
                [](Context &ctx) {
                    std::string store_id   = ctx.param("store_id");
                    std::string product_id = ctx.param("product_id");
                    std::string review_id  = ctx.param("review_id");

                    ctx.response.status_code = HTTP_STATUS_OK;
                    ctx.response.body()      = "Review: " + review_id +
                                          " for product: " + product_id +
                                          " in store: " + store_id;
                });

    // Test niveau 1 - Magasin
    {
        // Réinitialiser la session pour ce test
        session->_response = qb::http::Response();

        TestRequest req;
        req.method = HTTP_GET;
        req._uri   = qb::io::uri("/stores/s123");

        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Store: s123");
    }

    // Test niveau 2 - Produit dans un magasin
    {
        // Réinitialiser la session pour ce test
        session->_response = qb::http::Response();

        TestRequest req;
        req.method = HTTP_GET;
        req._uri   = qb::io::uri("/stores/s123/products/p456");

        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(),
                  "Product: p456 in store: s123");
    }

    // Test niveau 3 - Avis sur un produit dans un magasin
    {
        // Réinitialiser la session pour ce test
        session->_response = qb::http::Response();

        TestRequest req;
        req.method = HTTP_GET;
        req._uri   = qb::io::uri("/stores/s123/products/p456/reviews/r789");

        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(),
                  "Review: r789 for product: p456 in store: s123");
    }
}

// Test controller with multiple HTTP methods
TEST_F(RouterTest, ControllerWithMultipleMethods) {
    class ApiController : public TestRouter::Controller {
    public:
        ApiController()
            : TestRouter::Controller("/api") {
            // get request
            router().get("/resources", [](TestRouter::Context &ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body()      = "List resources";
            });

            // post request
            router().post("/resources", [](TestRouter::Context &ctx) {
                ctx.response.status_code = HTTP_STATUS_CREATED;
                ctx.response.body()      = "Create resource";
            });

            // PUT request
            router().put("/resources/:id", [](TestRouter::Context &ctx) {
                auto id                  = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body()      = "Update resource: " + id;
            });

            // DELETE request
            router().del("/resources/:id", [](TestRouter::Context &ctx) {
                auto id                  = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_NO_CONTENT;
            });
        }
    };

    router->controller<ApiController>();

    // Test get
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri   = qb::io::uri("/api/resources");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "List resources");
    }

    // Test post
    {
        TestRequest req;
        req.method = HTTP_POST;
        req._uri   = qb::io::uri("/api/resources");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_CREATED);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Create resource");
    }

    // Test PUT
    {
        TestRequest req;
        req.method = HTTP_PUT;
        req._uri   = qb::io::uri("/api/resources/123");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Update resource: 123");
    }

    // Test DELETE
    {
        TestRequest req;
        req.method = HTTP_DELETE;
        req._uri   = qb::io::uri("/api/resources/123");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_NO_CONTENT);
    }
}

// Test parameter extraction in nested routes
TEST_F(RouterTest, ParameterExtractionInNestedRoutes) {
    class UserOrdersController : public TestRouter::Controller {
    public:
        UserOrdersController()
            : TestRouter::Controller("/users") {
            router().get("/:user_id", [](TestRouter::Context &ctx) {
                auto user_id             = ctx.param("user_id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body()      = "User: " + user_id;
            });

            // Nested orders under users
            router().get("/:user_id/orders/:order_id", [](TestRouter::Context &ctx) {
                auto user_id  = ctx.param("user_id");
                auto order_id = ctx.param("order_id");

                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "Order: " + order_id + " for user: " + user_id;
            });

            router().get("/:user_id/orders/:order_id/items/:item_id",
                         [](TestRouter::Context &ctx) {
                             auto user_id  = ctx.param("user_id");
                             auto order_id = ctx.param("order_id");
                             auto item_id  = ctx.param("item_id");

                             ctx.response.status_code = HTTP_STATUS_OK;
                             ctx.response.body()      = "Item: " + item_id +
                                                   " in order: " + order_id +
                                                   " for user: " + user_id;
                         });
        }
    };

    router->controller<UserOrdersController>();

    // Test parameter extraction in nested route
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri   = qb::io::uri("/users/john/orders/12345");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(),
                  "Order: 12345 for user: john");
    }

    // Test multiple parameters across nested routes
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri   = qb::io::uri("/users/john/orders/12345/items/6789");
        EXPECT_TRUE(router->route(session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(),
                  "Item: 6789 in order: 12345 for user: john");
    }
}

int
main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
/*
 * qb - C++ Actor Framework
 * Copyright (C) 2011-2023 isndev (www.qbaf.io). All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *         limitations under the License.
 */

#include "../http.h"
#include "../router.h"
#include <gtest/gtest.h>
#include <qb/io/uri.h>
#include <memory>

// Mock session for testing
struct MockSession {
    qb::http::Response& response() { return _response; }
    qb::http::Response _response;

    MockSession& operator<<(qb::http::Response const& response) {
        _response = std::move(qb::http::Response(response));
        return *this;
    }
};

// Test types
using TestRequest = qb::http::TRequest<std::string>;
using TestRouter = TestRequest::Router<MockSession>;
using Context = TestRouter::Context;

class RouterTest : public ::testing::Test {
protected:
    std::unique_ptr<TestRouter> router;
    std::unique_ptr<MockSession> session;

    void SetUp() override {
        session = std::make_unique<MockSession>();
        router = std::make_unique<TestRouter>();
    }
};

// Test basic routing with different HTTP methods
TEST_F(RouterTest, BasicRouting) {
    bool get_called = false;
    bool post_called = false;
    bool put_called = false;
    bool del_called = false;

    // Register routes using lambda functions
    router->GET("/test", [&](Context &ctx) {
        get_called = true;
        ctx.response.status_code = HTTP_STATUS_OK;
    });

    router->POST("/test", [&](Context &ctx) {
        post_called = true;
        ctx.response.status_code = HTTP_STATUS_CREATED;
    });

    router->PUT("/test", [&](Context &ctx) {
        put_called = true;
        ctx.response.status_code = HTTP_STATUS_OK;
    });

    router->DELETE("/test", [&](Context &ctx) {
        del_called = true;
        ctx.response.status_code = HTTP_STATUS_NO_CONTENT;
    });

    // Test GET
    TestRequest req;
    req.method = HTTP_GET;
    req._uri = qb::io::uri("/test");
    EXPECT_TRUE(router->route(*session, req));
    EXPECT_TRUE(get_called);
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);

    // Test POST
    req.method = HTTP_POST;
    EXPECT_TRUE(router->route(*session, req));
    EXPECT_TRUE(post_called);
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_CREATED);

    // Test PUT
    req.method = HTTP_PUT;
    EXPECT_TRUE(router->route(*session, req));
    EXPECT_TRUE(put_called);
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);

    // Test DELETE
    req.method = HTTP_DELETE;
    EXPECT_TRUE(router->route(*session, req));
    EXPECT_TRUE(del_called);
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_NO_CONTENT);
}

// Test route parameters
TEST_F(RouterTest, RouteParameters) {
    std::string user_id;
    std::string post_id;

    router->GET("/users/:id/posts/:post_id", [&](Context &ctx) {
        user_id = ctx.param("id");
        post_id = ctx.param("post_id");
        ctx.response.status_code = HTTP_STATUS_OK;
    });

    TestRequest req;
    req.method = HTTP_GET;
    req._uri = qb::io::uri("/users/123/posts/456");
    EXPECT_TRUE(router->route(*session, req));
    EXPECT_EQ(user_id, "123");
    EXPECT_EQ(post_id, "456");
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
}

// Test controller
TEST_F(RouterTest, Controller) {
    class UserController : public TestRouter::Controller {
    public:
        UserController() : TestRouter::Controller("/users") {
            router().GET("/", [](TestRouter::Context &ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "List of users";
            });

            router().GET("/:id", [](TestRouter::Context &ctx) {
                auto id = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "User details for ID: " + id;
            });
        }
    };

    router->controller<UserController>();

    // Test list users
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/users");
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "List of users");
    }

    // Test get user by id
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/users/123");
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "User details for ID: 123");
    }
}

// Test custom route class
TEST_F(RouterTest, CustomRoute) {
    struct CustomRoute : public TestRouter::Route {
        CustomRoute() : TestRouter::Route("/custom") {}

        void process(Context &ctx) override {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "Custom route response";
        }
    };

    router->GET<CustomRoute>();

    TestRequest req;
    req.method = HTTP_GET;
    req._uri = qb::io::uri("/custom");
    EXPECT_TRUE(router->route(*session, req));
    EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
    EXPECT_EQ(session->_response.body().as<std::string>(), "Custom route response");
}

// Test nested controllers
TEST_F(RouterTest, NestedControllers) {
    class ProductController : public TestRouter::Controller {
    public:
        ProductController() : TestRouter::Controller("/products") {
            router().GET("/", [](TestRouter::Context &ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "List of products";
            });

            router().GET("/:id", [](TestRouter::Context &ctx) {
                auto id = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "Product details for ID: " + id;
            });
        }
        
        // Constructor with a route prefix for nesting
        ProductController(const std::string& prefix) : TestRouter::Controller(prefix + "/products") {
            router().GET("/", [](TestRouter::Context &ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "List of products";
            });

            router().GET("/:id", [](TestRouter::Context &ctx) {
                auto id = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "Product details for ID: " + id;
            });
        }
    };
    
    class CategoryController : public TestRouter::Controller {
    public:
        CategoryController() : TestRouter::Controller("/categories") {
            router().GET("/", [](TestRouter::Context &ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "List of categories";
            });
            
            router().GET("/:id", [](TestRouter::Context &ctx) {
                auto id = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "Category details for ID: " + id;
            });
            
            // Add products under a specific category
            router().GET("/:category_id/products", [](TestRouter::Context &ctx) {
                auto category_id = ctx.param("category_id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "Products in category: " + category_id;
            });
            
            router().GET("/:category_id/products/:id", [](TestRouter::Context &ctx) {
                auto category_id = ctx.param("category_id");
                auto id = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "Product ID: " + id + " in category: " + category_id;
            });
        }
    };
    
    router->controller<CategoryController>();
    router->controller<ProductController>();
    
    // Test list categories
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/categories");
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "List of categories");
    }
    
    // Test get category by id
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/categories/electronics");
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Category details for ID: electronics");
    }
    
    // Test list products in a category
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/categories/electronics/products");
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Products in category: electronics");
    }
    
    // Test get product by id in a category
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/categories/electronics/products/123");
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Product ID: 123 in category: electronics");
    }
    
    // Test normal products endpoint
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/products/456");
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Product details for ID: 456");
    }
}

// Test multiple levels of nested controllers
TEST_F(RouterTest, MultiLevelNestedControllers) {
    // Route de niveau 1 - Magasin
    router->GET("/stores/:store_id", [](Context &ctx) {
        std::string store_id = ctx.param("store_id");
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Store: " + store_id;
    });
    
    // Route de niveau 2 - Produit dans un magasin
    router->GET("/stores/:store_id/products/:product_id", [](Context &ctx) {
        std::string store_id = ctx.param("store_id");
        std::string product_id = ctx.param("product_id");
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Product: " + product_id + " in store: " + store_id;
    });
    
    // Route de niveau 3 - Avis sur un produit dans un magasin
    router->GET("/stores/:store_id/products/:product_id/reviews/:review_id", [](Context &ctx) {
        std::string store_id = ctx.param("store_id");
        std::string product_id = ctx.param("product_id");
        std::string review_id = ctx.param("review_id");
        
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Review: " + review_id + " for product: " + product_id + " in store: " + store_id;
    });
    
    // Test niveau 1 - Magasin
    {
        // Réinitialiser la session pour ce test
        session->_response = qb::http::Response();
        
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/stores/s123");
        
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Store: s123");
    }
    
    // Test niveau 2 - Produit dans un magasin
    {
        // Réinitialiser la session pour ce test
        session->_response = qb::http::Response();
        
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/stores/s123/products/p456");
        
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Product: p456 in store: s123");
    }
    
    // Test niveau 3 - Avis sur un produit dans un magasin
    {
        // Réinitialiser la session pour ce test
        session->_response = qb::http::Response();
        
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/stores/s123/products/p456/reviews/r789");
        
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Review: r789 for product: p456 in store: s123");
    }
}

// Test controller with multiple HTTP methods
TEST_F(RouterTest, ControllerWithMultipleMethods) {
    class ApiController : public TestRouter::Controller {
    public:
        ApiController() : TestRouter::Controller("/api") {
            // GET request
            router().GET("/resources", [](TestRouter::Context &ctx) {
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "List resources";
            });
            
            // POST request
            router().POST("/resources", [](TestRouter::Context &ctx) {
                ctx.response.status_code = HTTP_STATUS_CREATED;
                ctx.response.body() = "Create resource";
            });
            
            // PUT request
            router().PUT("/resources/:id", [](TestRouter::Context &ctx) {
                auto id = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "Update resource: " + id;
            });
            
            // DELETE request
            router().DELETE("/resources/:id", [](TestRouter::Context &ctx) {
                auto id = ctx.param("id");
                ctx.response.status_code = HTTP_STATUS_NO_CONTENT;
            });
        }
    };
    
    router->controller<ApiController>();
    
    // Test GET
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/api/resources");
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "List resources");
    }
    
    // Test POST
    {
        TestRequest req;
        req.method = HTTP_POST;
        req._uri = qb::io::uri("/api/resources");
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_CREATED);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Create resource");
    }
    
    // Test PUT
    {
        TestRequest req;
        req.method = HTTP_PUT;
        req._uri = qb::io::uri("/api/resources/123");
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Update resource: 123");
    }
    
    // Test DELETE
    {
        TestRequest req;
        req.method = HTTP_DELETE;
        req._uri = qb::io::uri("/api/resources/123");
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_NO_CONTENT);
    }
}

// Test parameter extraction in nested routes
TEST_F(RouterTest, ParameterExtractionInNestedRoutes) {
    class UserOrdersController : public TestRouter::Controller {
    public:
        UserOrdersController() : TestRouter::Controller("/users") {
            router().GET("/:user_id", [](TestRouter::Context &ctx) {
                auto user_id = ctx.param("user_id");
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "User: " + user_id;
            });
            
            // Nested orders under users
            router().GET("/:user_id/orders/:order_id", [](TestRouter::Context &ctx) {
                auto user_id = ctx.param("user_id");
                auto order_id = ctx.param("order_id");
                
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "Order: " + order_id + " for user: " + user_id;
            });
            
            router().GET("/:user_id/orders/:order_id/items/:item_id", [](TestRouter::Context &ctx) {
                auto user_id = ctx.param("user_id");
                auto order_id = ctx.param("order_id");
                auto item_id = ctx.param("item_id");
                
                ctx.response.status_code = HTTP_STATUS_OK;
                ctx.response.body() = "Item: " + item_id + " in order: " + order_id + " for user: " + user_id;
            });
        }
    };
    
    router->controller<UserOrdersController>();
    
    // Test parameter extraction in nested route
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/users/john/orders/12345");
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Order: 12345 for user: john");
    }
    
    // Test multiple parameters across nested routes
    {
        TestRequest req;
        req.method = HTTP_GET;
        req._uri = qb::io::uri("/users/john/orders/12345/items/6789");
        EXPECT_TRUE(router->route(*session, req));
        EXPECT_EQ(session->_response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(session->_response.body().as<std::string>(), "Item: 6789 in order: 12345 for user: john");
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
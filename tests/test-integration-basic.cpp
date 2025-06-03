#include <gtest/gtest.h>
#include "../http.h" // Main HTTP header
#include "../routing/router.h" // New Router
#include "../routing/context.h" // New Context
#include <thread>
#include <atomic>
#include <chrono>
#include <iostream> // For std::cout

// Counters to track request processing
std::atomic<int> request_count_server{0};
std::atomic<int> request_count_client{0};
std::atomic<bool> server_ready{false};

// Test assertion counters for server-side validation
std::atomic<int> server_side_assertions{0};
std::atomic<int> expected_server_assertions{0};

// Helper to give a bit of time for server to process, if needed.
void short_sleep_for_server_processing() {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// Forward declaration
class BasicIntegrationServer;

// HTTP session class that handles client connections
// It now needs to process requests using the router from BasicIntegrationServer
class BasicIntegrationSession : public qb::http::use<BasicIntegrationSession>::session<BasicIntegrationServer> {
public:
    BasicIntegrationSession(BasicIntegrationServer &server_ref)
        : session(server_ref) {
    }
};

// HTTP server that listens for connections and configures routes using the new Router API
class BasicIntegrationServer : public qb::http::use<BasicIntegrationServer>::server<BasicIntegrationSession> {
public:
    // SessionType alias for convenience in lambdas
    using SessionContext = qb::http::Context<BasicIntegrationSession>;

    BasicIntegrationServer()
        : qb::http::use<BasicIntegrationServer>::server<BasicIntegrationSession>() {
        // Configure routes for testing different methods and status codes
        // Logging is now typically handled by middleware or within handlers if needed.
        // The old router().enable_logging(true) is not directly applicable.

        std::cout << "Setting up routes in the server using new routing API..." << std::endl;

        // 1. Basic GET route
        router().get("/test", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "GET Success";
            ctx->response().add_header("X-Test-Header", "test-value");
            request_count_server++;
            ctx->complete();
        });

        // 2. POST route
        router().post("/test", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::CREATED;
            ctx->response().body() = ctx->request().body();
            ctx->response().add_header("Content-Type", "application/json");
            request_count_server++;

            if (!ctx->request().body().empty()) {
                if (ctx->request().body().template as<std::string>() == "{\"test\": \"data\"}") {
                    server_side_assertions++;
                }
            }
            ctx->complete();
        });

        // 3. PUT route with single path parameter
        router().put("/test/:id", [](std::shared_ptr<SessionContext> ctx) {
            std::string id = ctx->path_param("id");
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "PUT Success for ID: " + id;
            request_count_server++;

            if (id == "123") {
                server_side_assertions++;
            }
            ctx->complete();
        });

        // 4. DELETE handler
        router().del("/test/:id", [](std::shared_ptr<SessionContext> ctx) {
            std::string id = ctx->path_param("id");
            ctx->response().status() = qb::http::status::NO_CONTENT;
            request_count_server++;

            if (id == "456") {
                server_side_assertions++;
            }
            ctx->complete();
        });

        // 5. Route with query parameters
        router().get("/query", [](std::shared_ptr<SessionContext> ctx) {
            std::string name = ctx->request().query("name");
            std::string age = ctx->request().query("age");
            std::string sort = ctx->request().query("sort", 0, "default"); // Query with default

            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "Query params - name: " + name + ", age: " + age + ", sort: " + sort;
            ctx->response().add_header("X-Query-Count", std::to_string(ctx->request().queries().size()));
            request_count_server++;

            if (name == "test" && age == "25" && sort == "asc") {
                server_side_assertions++;
            }
            ctx->complete();
        });

        // 6. Synchronous route (must call complete)
        router().get("/sync-no-complete", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "Sync response without explicit complete call"; // Body content same
            ctx->response().add_header("X-Complete-Type", "implicit"); // Header same
            request_count_server++;
            ctx->complete(); // MUST call complete now
        });

        // 7. Error handler
        router().get("/error", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
            ctx->response().body() = "Intentional error";
            request_count_server++;
            ctx->complete();
        });

        // 8. Async route
        router().get("/async", [](std::shared_ptr<SessionContext> ctx) {
            request_count_server++;
            // The handler itself is responsible for calling ctx->complete()
            // For async operations, capture ctx and call complete in the callback.
            qb::io::async::callback([ctx_capture = ctx]() {
                ctx_capture->response().status() = qb::http::status::OK;
                ctx_capture->response().body() = "Async response";
                ctx_capture->response().add_header("X-Async", "true");
                ctx_capture->complete();
            }, 0.1); // 100ms delay
        });

        // 9. Route Group Test
        auto api_group = router().group("/api/v1");
        api_group->get("/status", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "API Status: OK";
            ctx->response().add_header("X-Route-Type", "group");
            request_count_server++;
            ctx->complete();
        });

        // 10. Cookie setting test
        router().get("/cookie-set", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "Cookie has been set";

            ctx->response().add_cookie("test_cookie", "cookie_value");
            ctx->response().add_cookie(qb::http::Cookie{"test_cookie_with_attrs", "value_with_attrs"}
                .path("/")
                .http_only(true)
                .max_age(3600));

            request_count_server++;
            server_side_assertions++;
            ctx->complete();
        });

        // 11. Cookie reading test
        router().get("/cookie-read", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            std::string cookie_value = ctx->request().cookie_value("test_cookie");
            ctx->response().body() = "Cookie value: " + cookie_value;
            request_count_server++;

            if (cookie_value == "cookie_value") {
                server_side_assertions++;
            }
            ctx->complete();
        });

        // 12. JSON content type test
        router().get("/json", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().add_header("Content-Type", "application/json");

            qb::json json_obj = {
                {"message", "This is JSON"},
                {"success", true},
                {"code", 200}
            };

            ctx->response().body() = json_obj;
            request_count_server++;
            server_side_assertions++;
            ctx->complete();
        });

        // 13. Request headers echo
        router().get("/echo-headers", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().add_header("Content-Type", "application/json");

            qb::json headers_json = qb::json::object();
            for (const auto &header_pair: ctx->request().headers()) {
                const auto &name = header_pair.first;
                const auto &values = header_pair.second;

                if (values.size() == 1) {
                    headers_json[name] = values[0];
                } else {
                    headers_json[name] = qb::json::array();
                    for (const auto &value: values) {
                        headers_json[name].push_back(value);
                    }
                }
            }

            ctx->response().body() = headers_json;
            request_count_server++;

            if (ctx->request().header("X-Custom-Header") == "test-value" ||
                ctx->request().header("x-custom-header") == "test-value") {
                server_side_assertions++;
            }
            ctx->complete();
        });

        expected_server_assertions = 8;

        std::cout << "All routes configured successfully with new API" << std::endl;

        // Compile all routes
        router().compile();
    }
};

// Test Fixture for Basic HTTP Integration Tests
class HttpBasicIntegrationTest : public ::testing::Test {
protected:
    std::unique_ptr<BasicIntegrationServer> _server;
    std::thread _server_thread;
    static const int SERVER_PORT = 9876;

    // Per-test-case setup
    void SetUp() override {
        qb::io::async::init(); // Ensure async is init for the main test thread

        // Reset counters for each test
        request_count_server = 0;
        request_count_client = 0;
        server_side_assertions = 0;
        expected_server_assertions = 0; // Will be set by each test case
        server_ready = false;

        _server = std::make_unique<BasicIntegrationServer>();

        _server_thread = std::thread([]() {
            qb::io::async::init(); // Init for server thread

            BasicIntegrationServer server_instance; // Use a local instance for the thread
            server_instance.transport().listen_v4(SERVER_PORT);
            server_instance.start();

            server_ready = true;
            std::cout << "Server is ready and listening at port " << SERVER_PORT << std::endl;

            // Keep server running as long as server_ready is true.
            // The main test thread will set server_ready to false in TearDown.
            while (server_ready.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    // If no events, sleep a bit to avoid busy spinning
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
            std::cout << "Server thread shutting down." << std::endl;
        });

        // Wait for the server to be ready
        while (!server_ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        // Give a little extra time for the server to fully initialize routes, etc.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::cout << "HttpBasicIntegrationTest::SetUp complete." << std::endl;
    }

    // Per-test-case tear-down
    void TearDown() override {
        std::cout << "HttpBasicIntegrationTest::TearDown started." << std::endl;
        server_ready = false; // Signal server thread to stop
        if (_server_thread.joinable()) {
            _server_thread.join();
        }
        _server.reset(); // Clean up server object

        // Final check of assertions for the completed test
        if (expected_server_assertions > 0) {
            // Only check if assertions were expected
            EXPECT_EQ(expected_server_assertions.load(), server_side_assertions.load())
                << "Mismatch in server-side assertions for the test. Expected: "
                << expected_server_assertions.load() << ", Got: " << server_side_assertions.load();
        }
        std::cout << "Test finished. Client requests: " << request_count_client.load()
                << ", Server requests: " << request_count_server.load()
                << ", Server assertions: " << server_side_assertions.load()
                << " (expected: " << expected_server_assertions.load() << ")" << std::endl;
    }

    // Helper to make client requests - ensures server is ready
    template<typename Func>
    void MakeClientRequest(Func &&client_logic, int expected_server_req_increment = 1,
                           int expected_server_assert_increment = 0) {
        if (!server_ready) {
            FAIL() << "Server not ready before making client request.";
            return;
        }

        int current_server_req = request_count_server.load();
        int current_server_asserts = server_side_assertions.load();

        client_logic(); // Execute the client request logic

        request_count_client++;

        // Allow some time for server to process
        // This is a bit of a heuristic. A more robust solution might involve direct signals
        // or checking server counters with a timeout.
        std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Increased delay
        // especially for async tests

        // Check if server processed the request(s)
        // This check might be flaky for async handlers if the delay is too short.
        EXPECT_EQ(current_server_req + expected_server_req_increment, request_count_server.load())
            << "Server did not process the expected number of requests.";

        if (expected_server_assert_increment > 0) {
            EXPECT_EQ(current_server_asserts + expected_server_assert_increment, server_side_assertions.load())
                << "Server-side assertions did not increment as expected.";
        }
    }
};

const int HttpBasicIntegrationTest::SERVER_PORT; // Define static member

// --- Individual Test Cases ---

TEST_F(HttpBasicIntegrationTest, GetRequest) {
    expected_server_assertions = 0; // No specific server-side data checks here, only request count
    MakeClientRequest([] {
        std::cout << "Client: Sending GET request to /test" << std::endl;
        qb::http::Request request{{"http://localhost:9876/test"}};
        request.add_header("User-Agent", "Integration-Test/1.0");
        auto response = qb::http::GET(request);
        std::cout << "Client: Received GET response status: " << response.status() << std::endl;
        EXPECT_EQ(HTTP_STATUS_OK, response.status());
        EXPECT_EQ("GET Success", response.body().template as<std::string>());
        EXPECT_EQ("test-value", response.header("X-Test-Header"));
    });
}

TEST_F(HttpBasicIntegrationTest, PostRequest) {
    expected_server_assertions = 1; // For body content check
    MakeClientRequest([] {
        std::cout << "Client: Sending POST request to /test" << std::endl;
        qb::http::Request request{qb::http::method::POST, {"http://localhost:9876/test"}};
        request.add_header("Content-Type", "application/json");
        request.body() = "{\"test\": \"data\"}";
        auto response = qb::http::POST(request);
        std::cout << "Client: Received POST response status: " << response.status() << std::endl;
        EXPECT_EQ(HTTP_STATUS_CREATED, response.status());
        EXPECT_EQ("{\"test\": \"data\"}", response.body().template as<std::string>());
        EXPECT_EQ("application/json", response.header("Content-Type"));
    }, 1, 1);
}

TEST_F(HttpBasicIntegrationTest, PutRequestWithParam) {
    expected_server_assertions = 1; // For ID check
    MakeClientRequest([] {
        std::cout << "Client: Sending PUT request to /test/123" << std::endl;
        qb::http::Request request{qb::http::method::PUT, {"http://localhost:9876/test/123"}};
        auto response = qb::http::PUT(request);
        std::cout << "Client: Received PUT response status: " << response.status() << std::endl;
        EXPECT_EQ(HTTP_STATUS_OK, response.status());
        EXPECT_EQ("PUT Success for ID: 123", response.body().template as<std::string>());
    }, 1, 1);
}

TEST_F(HttpBasicIntegrationTest, DeleteRequestWithParam) {
    expected_server_assertions = 1; // For ID check
    MakeClientRequest([] {
        std::cout << "Client: Sending DELETE request to /test/456" << std::endl;
        qb::http::Request request{qb::http::method::DEL, {"http://localhost:9876/test/456"}};
        auto response = qb::http::DEL(request);
        std::cout << "Client: Received DELETE response status: " << response.status() << std::endl;
        EXPECT_EQ(HTTP_STATUS_NO_CONTENT, response.status());
        EXPECT_TRUE(response.body().empty());
    }, 1, 1);
}

TEST_F(HttpBasicIntegrationTest, GetWithQueryParameters) {
    expected_server_assertions = 1; // For query params check
    MakeClientRequest([] {
        std::cout << "Client: Sending GET request with query parameters" << std::endl;
        qb::http::Request request{{"http://localhost:9876/query?name=test&age=25&sort=asc"}};
        auto response = qb::http::GET(request);
        std::cout << "Client: Received query params response status: " << response.status() << std::endl;
        EXPECT_EQ(HTTP_STATUS_OK, response.status());
        EXPECT_EQ("Query params - name: test, age: 25, sort: asc", response.body().template as<std::string>());
        EXPECT_EQ("3", response.header("X-Query-Count"));
    }, 1, 1);
}

TEST_F(HttpBasicIntegrationTest, GetErrorRoute) {
    expected_server_assertions = 0; // No specific data check on server side for this other than count
    MakeClientRequest([] {
        std::cout << "Client: Sending GET request to /error" << std::endl;
        qb::http::Request request{{"http://localhost:9876/error"}};
        auto response = qb::http::GET(request, 5.0);
        std::cout << "Client: Received ERROR response status: " << response.status() << std::endl;
        EXPECT_EQ(HTTP_STATUS_INTERNAL_SERVER_ERROR, response.status());
        EXPECT_EQ("Intentional error", response.body().template as<std::string>());
    });
}

TEST_F(HttpBasicIntegrationTest, GetSyncRouteWithComplete) {
    expected_server_assertions = 0; // No specific data check
    MakeClientRequest([] {
        std::cout << "Client: Sending GET request to /sync-no-complete" << std::endl;
        qb::http::Request request{{"http://localhost:9876/sync-no-complete"}};
        auto response = qb::http::GET(request);
        std::cout << "Client: Received SYNC-NO-COMPLETE response status: " << response.status() << std::endl;
        EXPECT_EQ(HTTP_STATUS_OK, response.status());
        EXPECT_EQ("Sync response without explicit complete call", response.body().template as<std::string>());
        EXPECT_EQ("implicit", response.header("X-Complete-Type"));
    });
}

TEST_F(HttpBasicIntegrationTest, GetAsyncRoute) {
    expected_server_assertions = 0; // No specific data check
    MakeClientRequest([] {
        std::cout << "Client: Sending GET request to /async" << std::endl;
        qb::http::Request request{{"http://localhost:9876/async"}};
        // Increased timeout for async response
        auto response = qb::http::GET(request, 5.0);
        std::cout << "Client: Received ASYNC response status: " << response.status() << std::endl;
        EXPECT_EQ(HTTP_STATUS_OK, response.status());
        EXPECT_EQ("Async response", response.body().template as<std::string>());
        EXPECT_EQ("true", response.header("X-Async"));
    });
}

TEST_F(HttpBasicIntegrationTest, GetRouteGroup) {
    expected_server_assertions = 0; // No specific data check
    MakeClientRequest([] {
        std::cout << "Client: Testing route group - sending request to /api/v1/status" << std::endl;
        qb::http::Request request{{"http://localhost:9876/api/v1/status"}};
        auto response = qb::http::GET(request);
        std::cout << "Client: Received group route response status: " << response.status() << std::endl;
        EXPECT_EQ(HTTP_STATUS_OK, response.status());
        EXPECT_EQ("API Status: OK", response.body().template as<std::string>());
        EXPECT_EQ("group", response.header("X-Route-Type"));
    });
}

TEST_F(HttpBasicIntegrationTest, CookieSetting) {
    expected_server_assertions = 1; // For server-side increment on cookie set path
    MakeClientRequest([] {
        std::cout << "Client: Testing cookie setting" << std::endl;
        qb::http::Request request{{"http://localhost:9876/cookie-set"}};
        auto response = qb::http::GET(request);
        std::cout << "Client: Received cookie-set response status: " << response.status() << std::endl;
        EXPECT_EQ(HTTP_STATUS_OK, response.status());
        EXPECT_EQ("Cookie has been set", response.body().template as<std::string>());
        EXPECT_TRUE(response.cookie("test_cookie") != nullptr);
        EXPECT_EQ("cookie_value", response.cookie("test_cookie")->value());
        EXPECT_TRUE(response.cookie("test_cookie_with_attrs") != nullptr);
        EXPECT_EQ("value_with_attrs", response.cookie("test_cookie_with_attrs")->value());
        EXPECT_EQ("/", response.cookie("test_cookie_with_attrs")->path());
        EXPECT_TRUE(response.cookie("test_cookie_with_attrs")->http_only());
        EXPECT_EQ(3600, *(response.cookie("test_cookie_with_attrs")->max_age()));
    }, 1, 1);
}

TEST_F(HttpBasicIntegrationTest, CookieReading) {
    expected_server_assertions = 1; // For server-side validation of cookie value
    MakeClientRequest([] {
        std::cout << "Client: Testing cookie reading" << std::endl;
        qb::http::Request request{{"http://localhost:9876/cookie-read"}};
        request.add_header("Cookie", "test_cookie=cookie_value");
        auto response = qb::http::GET(request);
        std::cout << "Client: Received cookie-read response status: " << response.status() << std::endl;
        EXPECT_EQ(HTTP_STATUS_OK, response.status());
        EXPECT_EQ("Cookie value: cookie_value", response.body().template as<std::string>());
    }, 1, 1);
}

TEST_F(HttpBasicIntegrationTest, JsonContentType) {
    expected_server_assertions = 1; // For server-side increment on /json path
    MakeClientRequest([] {
        std::cout << "Client: Testing JSON response" << std::endl;
        qb::http::Request request{{"http://localhost:9876/json"}};
        auto response = qb::http::GET(request);
        std::cout << "Client: Received JSON response status: " << response.status() << std::endl;
        EXPECT_EQ(HTTP_STATUS_OK, response.status());
        EXPECT_EQ("application/json", response.header("Content-Type"));
        auto json_body = response.body().template as<qb::json>();
        EXPECT_EQ("This is JSON", json_body["message"]);
        EXPECT_EQ(true, json_body["success"]);
        EXPECT_EQ(200, json_body["code"]);
    }, 1, 1);
}

TEST_F(HttpBasicIntegrationTest, RequestHeadersEcho) {
    expected_server_assertions = 1; // For server-side validation of custom header
    MakeClientRequest([] {
        std::cout << "Client: Testing headers echo" << std::endl;
        qb::http::Request request{{"http://localhost:9876/echo-headers"}};
        request.add_header("X-Custom-Header", "test-value");
        request.add_header("User-Agent", "Echo-Headers-Test/1.0");
        auto response = qb::http::GET(request);
        std::cout << "Client: Received headers echo response status: " << response.status() << std::endl;
        EXPECT_EQ(HTTP_STATUS_OK, response.status());
        EXPECT_EQ("application/json", response.header("Content-Type"));
        auto headers_json_body = response.body().template as<qb::json>();
        EXPECT_TRUE(headers_json_body.contains("x-custom-header") ||
            headers_json_body.contains("X-Custom-Header"));
        EXPECT_TRUE(headers_json_body.contains("user-agent") ||
            headers_json_body.contains("User-Agent"));
    }, 1, 1);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

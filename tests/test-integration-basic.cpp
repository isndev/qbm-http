#include <gtest/gtest.h>
#include "../http.h"
#include <thread>
#include <atomic>
#include <chrono>

// Counters to track request processing
std::atomic<int> request_count_server{0};
std::atomic<int> request_count_client{0};
std::atomic<bool> server_ready{false};

// Test assertion counters for server-side validation
std::atomic<int> server_side_assertions{0}; 
std::atomic<int> expected_server_assertions{0};

// HTTP session class that handles client connections
class BasicIntegrationServer;
class BasicIntegrationSession : public qb::http::use<BasicIntegrationSession>::session<BasicIntegrationServer>
{
public:
    BasicIntegrationSession(BasicIntegrationServer &server)
        : session(server) {}
};

// HTTP server that listens for connections and configures routes
class BasicIntegrationServer : public qb::http::use<BasicIntegrationServer>::server<BasicIntegrationSession> {
public:
    using Router = qb::http::Router<BasicIntegrationSession>;
    using Context = qb::http::RouterContext<BasicIntegrationSession, std::string>;

    BasicIntegrationServer() {
        // Configure routes for testing different methods and status codes
        router().enable_logging(true);
        
        std::cout << "Setting up routes in the server..." << std::endl;
        
        // 1. Basic GET route without explicit complete
        router().get("/test", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "GET Success";
            ctx.response.add_header("X-Test-Header", "test-value");
            request_count_server++;
        });
        
        // 2. POST route without explicit complete
        router().post("/test", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_CREATED;
            ctx.response.body() = ctx.request.body();
            ctx.response.add_header("Content-Type", "application/json");
            request_count_server++;
            
            // Verify that the request body is valid JSON
            if (!ctx.request.body().empty()) {
                // Server-side assertion
                if (ctx.request.body().as<std::string>() == "{\"test\": \"data\"}") {
                    server_side_assertions++;
                }
            }
        });
        
        // 3. PUT route with single path parameter
        router().put("/test/:id", [](Context& ctx) {
            std::string id = ctx.param("id");
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "PUT Success for ID: " + id;
            request_count_server++;
            
            // Server-side assertion
            if (id == "123") {
                server_side_assertions++;
            }
        });
        
        // 4. DELETE handler with explicit complete
        router().del("/test/:id", [](Context& ctx) {
            std::string id = ctx.param("id");
            ctx.response.status_code = HTTP_STATUS_NO_CONTENT;
            request_count_server++;
            
            // Server-side assertion
            if (id == "456") {
                server_side_assertions++;
            }
            
            ctx.complete();
        });
        
        // 5. Route with query parameters
        router().get("/query", [](Context& ctx) {
            // Extract query parameters
            std::string name = ctx.request.query("name");
            std::string age = ctx.request.query("age");
            std::string sort = ctx.request.query("sort", 0, "default"); // With default value
            
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "Query params - name: " + name + ", age: " + age + ", sort: " + sort;
            ctx.response.add_header("X-Query-Count", std::to_string(ctx.request.queries().size()));
            request_count_server++;
            
            // Server-side assertion
            if (name == "test" && age == "25" && sort == "asc") {
                server_side_assertions++;
            }
        });
        
        // 6. Synchronous route without explicit complete
        router().get("/sync-no-complete", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "Sync response without explicit complete call";
            ctx.response.add_header("X-Complete-Type", "implicit");
            request_count_server++;
        });
        
        // 7. Error handler with explicit complete
        router().get("/error", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
            ctx.response.body() = "Intentional error";
            request_count_server++;
            ctx.complete();
        });
        
        // 8. Async route
        router().get("/async", [](Context& ctx) {
            // Make this request async
            auto async_handler = ctx.make_async();
            request_count_server++;
            
            // Schedule completion with delay
            qb::io::async::callback([handler = std::move(async_handler)]() {
                handler->status(HTTP_STATUS_OK);
                handler->body("Async response");
                handler->header("X-Async", "true");
                handler->complete();
            }, 0.1); // 100ms delay
        });
        
        // 9. Route Group Test
        auto api_group = router().group("/api/v1");
        api_group.get("/status", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "API Status: OK";
            ctx.response.add_header("X-Route-Type", "group");
            request_count_server++;
        });
        
        // Set expected server assertions
        expected_server_assertions = 4;  // Server-side assertions above
        
        std::cout << "All routes configured successfully" << std::endl;
    }
};

// Main HTTP integration test
TEST(HttpIntegration, BasicHttpFunctionality) {
    // Initialize async environment
    qb::io::async::init();
    
    // Reset counters
    request_count_server = 0;
    request_count_client = 0;
    server_ready = false;
    server_side_assertions = 0;
    
    // Start HTTP server in a separate thread
    std::thread server_thread([]() {
        qb::io::async::init();
        
        // Create and configure server
        BasicIntegrationServer server;
        server.transport().listen_v4(9876);
        server.start();
        
        // Indicate that server is ready
        server_ready = true;
        std::cout << "Server is ready and listening at port 9876" << std::endl;
        
        // Main event loop - process until all requests are handled with a maximum safety limit
        int max_iterations = 100;
        // Wait until we've processed all expected requests OR hit the safety limit
        // We're expecting: GET /test, POST /test, PUT /test/:id, DELETE /test/:id, 
        // GET /query, GET /sync-no-complete, GET /error, GET /async, GET /api/v1/status
        int expected_requests = 9;
        while ((request_count_server < expected_requests || request_count_client < expected_requests) && max_iterations > 0) {
            qb::io::async::run(EVRUN_ONCE);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            max_iterations--;
        }
        
        // Add a grace period to ensure all responses are fully sent
        std::cout << "Server processed all expected requests, allowing grace period for final responses..." << std::endl;
        for (int i = 0; i < 10; i++) {
            qb::io::async::run(EVRUN_ONCE);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        
        std::cout << "Server thread finished, processed " << request_count_server 
                  << " requests with " << server_side_assertions << " server-side assertions" << std::endl;
    });
    
    // Client thread that sends requests to the server
    std::thread client_thread([]() {
        // Wait for server to be ready
        while (!server_ready) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // Give server extra time to prepare
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        std::cout << "Client starting tests..." << std::endl;
        
        try {
            // 1. Test GET method with 200 code
            {
                std::cout << "Client: Sending GET request to /test" << std::endl;
                qb::http::Request request{{"http://localhost:9876/test"}};
                request.add_header("User-Agent", "Integration-Test/1.0");

                auto response = qb::http::GET(request);

                std::cout << "Client: Received GET response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("GET Success", response.body().as<std::string>());
                EXPECT_EQ("test-value", response.header("X-Test-Header"));
                request_count_client++;
            }

            // 2. Test POST method with 201 code
            {
                std::cout << "Client: Sending POST request to /test" << std::endl;
                qb::http::Request request{HTTP_POST, {"http://localhost:9876/test"}};
                request.add_header("Content-Type", "application/json");
                request.body() = "{\"test\": \"data\"}";

                auto response = qb::http::POST(request);

                std::cout << "Client: Received POST response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_CREATED, response.status_code);
                EXPECT_EQ("{\"test\": \"data\"}", response.body().as<std::string>());
                EXPECT_EQ("application/json", response.header("Content-Type"));
                request_count_client++;
            }

            // 3. Test PUT method with URL parameter
            {
                std::cout << "Client: Sending PUT request to /test/123" << std::endl;
                qb::http::Request request{HTTP_PUT, {"http://localhost:9876/test/123"}};

                auto response = qb::http::PUT(request);

                std::cout << "Client: Received PUT response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("PUT Success for ID: 123", response.body().as<std::string>());
                request_count_client++;
            }

            // 4. Test DELETE method with 204 code
            {
                std::cout << "Client: Sending DELETE request to /test/456" << std::endl;
                qb::http::Request request{HTTP_DELETE, {"http://localhost:9876/test/456"}};

                auto response = qb::http::DELETE(request);

                std::cout << "Client: Received DELETE response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_NO_CONTENT, response.status_code);
                EXPECT_TRUE(response.body().empty());
                request_count_client++;
            }
            
            // 5. Test query parameters
            {
                std::cout << "Client: Sending GET request with query parameters" << std::endl;
                qb::http::Request request{{"http://localhost:9876/query?name=test&age=25&sort=asc"}};

                auto response = qb::http::GET(request);

                std::cout << "Client: Received query params response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("Query params - name: test, age: 25, sort: asc", response.body().as<std::string>());
                EXPECT_EQ("3", response.header("X-Query-Count"));
                request_count_client++;
            }
            
            // 6. Test error code 500
            {
                std::cout << "Client: Sending GET request to /error" << std::endl;
                qb::http::Request request{{"http://localhost:9876/error"}};
                
                auto response = qb::http::GET(request, 5.0);
                
                std::cout << "Client: Received ERROR response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_INTERNAL_SERVER_ERROR, response.status_code);
                EXPECT_EQ("Intentional error", response.body().as<std::string>());
                request_count_client++;
            }
            
            // 7. Test sync route without explicit complete
            {
                std::cout << "Client: Sending GET request to /sync-no-complete" << std::endl;
                qb::http::Request request{{"http://localhost:9876/sync-no-complete"}};
                
                auto response = qb::http::GET(request);
                
                std::cout << "Client: Received SYNC-NO-COMPLETE response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("Sync response without explicit complete call", response.body().as<std::string>());
                EXPECT_EQ("implicit", response.header("X-Complete-Type"));
                request_count_client++;
            }
            
            // 8. Test async route
            {
                std::cout << "Client: Sending GET request to /async" << std::endl;
                qb::http::Request request{{"http://localhost:9876/async"}};
                
                auto response = qb::http::GET(request, 3.0); // Longer timeout for async
                
                std::cout << "Client: Received ASYNC response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("Async response", response.body().as<std::string>());
                EXPECT_EQ("true", response.header("X-Async"));
                request_count_client++;
            }
            
            // 9. Test Route Group
            {
                std::cout << "Client: Testing route group - sending request to /api/v1/status" << std::endl;
                qb::http::Request request{{"http://localhost:9876/api/v1/status"}};
                
                auto response = qb::http::GET(request);
                
                std::cout << "Client: Received group route response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("API Status: OK", response.body().as<std::string>());
                EXPECT_EQ("group", response.header("X-Route-Type"));
                request_count_client++;
            }
            
            std::cout << "Client thread completed, processed " << request_count_client << " requests" << std::endl;
            
        } catch (const std::exception& e) {
            std::cout << "Client exception: " << e.what() << std::endl;
            FAIL() << "Client test exception: " << e.what();
        }
    });
    
    // Wait for threads to complete
    client_thread.join();
    server_thread.join();
    
    // Verify all tests were executed
    EXPECT_EQ(9, request_count_client.load());
    EXPECT_EQ(9, request_count_server.load());
    
    // Verify server-side assertions
    EXPECT_EQ(expected_server_assertions, server_side_assertions.load());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
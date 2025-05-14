#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/middleware.h"
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

// Additional counters for advanced features
std::atomic<int> async_operations_completed{0};
std::atomic<int> middleware_executions{0};

// Rate limiting (simple in-memory store)
std::map<std::string, int> rate_limit_counters;

// HTTP session class that handles client connections
class AdvancedIntegrationServer;
class AdvancedIntegrationSession : public qb::http::use<AdvancedIntegrationSession>::session<AdvancedIntegrationServer>
{
public:
    AdvancedIntegrationSession(AdvancedIntegrationServer &server)
        : session(server) {}
};

// HTTP server that listens for connections and configures routes
class AdvancedIntegrationServer : public qb::http::use<AdvancedIntegrationServer>::server<AdvancedIntegrationSession> {
public:
    using Router = qb::http::Router<AdvancedIntegrationSession>;
    using Context = qb::http::RouterContext<AdvancedIntegrationSession, std::string>;

    AdvancedIntegrationServer() {
        // Configure routes for testing different methods and status codes
        router().enable_logging(true);
        
        std::cout << "Setting up advanced routes in the server..." << std::endl;
        
        // ------- Middleware Configuration -------
        
        // 1. Authentication Middleware
        router().use([](Context& ctx) {
            middleware_executions++;
            
            // Check for auth token in header
            std::string auth_header = ctx.request.header("Authorization");
            
            // No auth needed for public routes
            if (ctx.request.uri().path().find("/public/") == 0) {
                return true;
            }
            
            // Auth required for protected routes
            if (ctx.request.uri().path().find("/protected/") == 0) {
                if (auth_header.empty()) {
                    ctx.response.status_code = HTTP_STATUS_UNAUTHORIZED;
                    ctx.response.body() = "Authentication required";
                    ctx.handled = true;
                    return false;
                }
                
                // Simple token validation
                if (auth_header != "Bearer valid-token") {
                    ctx.response.status_code = HTTP_STATUS_FORBIDDEN;
                    ctx.response.body() = "Invalid authorization token";
                    ctx.handled = true;
                    return false;
                }
                
                // Store user info in context
                ctx.set<std::string>("user_id", "test-user-123");
                ctx.set<bool>("is_admin", true);
            }
            
            return true;
        });
        
        // 2. Rate Limiting Middleware
        router().use([](Context& ctx) {
            middleware_executions++;
            
            // Get client IP (in a real app, this would be from request)
            std::string client_ip = ctx.request.header("X-Client-IP", 0, "127.0.0.1");
            
            // Check if route should be rate limited
            if (ctx.request.uri().path().find("/rate-limited/") == 0) {
                // Allow max 3 requests per IP
                if (rate_limit_counters[client_ip]++ >= 3) {
                    ctx.response.status_code = HTTP_STATUS_TOO_MANY_REQUESTS;
                    ctx.response.body() = "Rate limit exceeded";
                    ctx.handled = true;
                    return false;
                }
            }
            
            return true;
        });
        
        // ------- Route Configurations -------
        
        // 1. Public routes (no auth required)
        router().get("/public/info", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "Public API information";
            request_count_server++;
        });
        
        // 2. Protected routes (require authentication)
        router().get("/protected/profile", [](Context& ctx) {
            std::string user_id = ctx.get<std::string>("user_id");
            bool is_admin = ctx.get<bool>("is_admin");
            
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = qb::json{
                {"user_id", user_id},
                {"is_admin", is_admin},
                {"profile", "User profile data"}
            };
            
            ctx.response.add_header("Content-Type", "application/json");
            request_count_server++;
            
            // Server-side assertion
            server_side_assertions++;
        });
        
        // 3. Rate-limited routes
        router().get("/rate-limited/resource", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "Rate-limited resource accessed successfully";
            request_count_server++;
        });
        
        // 4. Async routes with different delay times
        router().get("/async/delay/:milliseconds", [](Context& ctx) {
            auto completion = ctx.make_async();
            std::string ms_str = ctx.param("milliseconds");
            
            int delay_ms = 300; // Default value if conversion fails
            try {
                delay_ms = std::stoi(ms_str);
            } catch (const std::exception& e) {
                std::cerr << "Error converting delay parameter to integer: " << e.what() << std::endl;
                // Continue with default value
            }
            
            // Cap the delay to prevent test timeouts
            delay_ms = std::min(delay_ms, 1000);
            
            // Schedule async completion
            qb::io::async::callback([completion, delay_ms]() {
                completion->status(HTTP_STATUS_OK)
                    .header("X-Delay-MS", std::to_string(delay_ms))
                    .body("Delayed response after " + std::to_string(delay_ms) + "ms")
                    .complete();
                    
                async_operations_completed++;
            }, delay_ms / 1000.0);
            
            request_count_server++;
        });
        
        // 5. Basic GET route without explicit complete
        router().get("/test", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "GET Success";
            ctx.response.add_header("X-Test-Header", "test-value");
            request_count_server++;
        });
        
        // 6. POST route without explicit complete
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
        
        // 7. PUT route with single path parameter
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
        
        // 8. DELETE handler with explicit complete
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
        
        // 9. Route with query parameters
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
        
        // 10. Synchronous route without explicit complete
        router().get("/sync-no-complete", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "Sync response without explicit complete call";
            ctx.response.add_header("X-Complete-Type", "implicit");
            request_count_server++;
        });
        
        // 11. Error handler with explicit complete
        router().get("/error", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
            ctx.response.body() = "Intentional error";
            request_count_server++;
            ctx.complete();
        });
        
        // 12. Async route
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
        
        // 13. Route Group Test
        auto api_group = router().group("/api/v1");
        api_group.get("/status", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "API Status: OK";
            ctx.response.add_header("X-Route-Type", "group");
            request_count_server++;
        });
        
        // 14. Cookie setting test
        router().get("/cookie-set", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "Cookie has been set";
            
            // Set a test cookie with some attributes
            ctx.response.add_cookie("test_cookie", "cookie_value");
            ctx.response.add_cookie(qb::http::Cookie{"test_cookie_with_attrs", "value_with_attrs"}
                     .path("/")
                     .http_only(true)
                     .max_age(3600));
            
            request_count_server++;
            
            // Server-side assertion for cookie logic
            server_side_assertions++;
        });
        
        // 15. Cookie reading test
        router().get("/cookie-read", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            
            // Read the cookie
            std::string cookie_value = ctx.request.cookie_value("test_cookie");
            
            // Return the cookie value in the response
            ctx.response.body() = "Cookie value: " + cookie_value;
            request_count_server++;
            
            // Server-side assertion
            if (cookie_value == "cookie_value") {
                server_side_assertions++;
            }
        });
        
        // 16. JSON content type test
        router().get("/json", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.add_header("Content-Type", "application/json");
            
            // Create a JSON response
            qb::json json_obj = {
                {"message", "This is JSON"},
                {"success", true},
                {"code", 200}
            };
            
            ctx.response.body() = json_obj;
            request_count_server++;
            
            // Server-side assertion
            server_side_assertions++;
        });
        
        // 17. Request headers echo
        router().get("/echo-headers", [](Context& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.add_header("Content-Type", "application/json");
            
            // Create JSON representation of headers
            qb::json headers_json = qb::json::object();
            for (const auto& header_pair : ctx.request.headers()) {
                const auto& name = header_pair.first;
                const auto& values = header_pair.second;
                
                if (values.size() == 1) {
                    headers_json[name] = values[0];
                } else {
                    headers_json[name] = qb::json::array();
                    for (const auto& value : values) {
                        headers_json[name].push_back(value);
                    }
                }
            }
            
            ctx.response.body() = headers_json;
            request_count_server++;
            
            // Server-side assertion - test for custom header
            if (ctx.request.header("X-Custom-Header") == "test-value" ||
                ctx.request.header("x-custom-header") == "test-value") {
                server_side_assertions++;
            }
        });
        
        // Set expected server assertions
        expected_server_assertions = 9; // Update based on the number of server-side assertions added
        
        std::cout << "All advanced routes configured successfully" << std::endl;
    }
};

// Main HTTP advanced integration test
TEST(HttpIntegration, AdvancedHttpFunctionality) {
    // Initialize async environment
    qb::io::async::init();
    
    // Reset counters
    request_count_server = 0;
    request_count_client = 0;
    server_ready = false;
    server_side_assertions = 0;
    async_operations_completed = 0;
    middleware_executions = 0;
    rate_limit_counters.clear();
    
    // Start HTTP server in a separate thread
    std::thread server_thread([]() {
        qb::io::async::init();
        
        // Create and configure server
        AdvancedIntegrationServer server;
        server.transport().listen_v4(9877); // Use different port from basic test
        server.start();
        
        // Indicate that server is ready
        server_ready = true;
        std::cout << "Advanced server is ready and listening at port 9877" << std::endl;
        
        // Main event loop - process until all requests are handled with a maximum safety limit
        int max_iterations = 500; // Plus d'itérations pour éviter un blocage
        int expected_server_requests = 19; // Expected number of server-side requests
        int expected_client_requests = 18; // Exact number of client-side test cases
        
        while ((request_count_server < expected_server_requests || 
                request_count_client < expected_client_requests) && 
               max_iterations > 0) {
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
        std::cout << "Async operations completed: " << async_operations_completed
                  << ", Middleware executions: " << middleware_executions << std::endl;
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
                qb::http::Request request{{"http://localhost:9877/test"}};
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
                qb::http::Request request{HTTP_POST, {"http://localhost:9877/test"}};
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
                qb::http::Request request{HTTP_PUT, {"http://localhost:9877/test/123"}};

                auto response = qb::http::PUT(request);

                std::cout << "Client: Received PUT response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("PUT Success for ID: 123", response.body().as<std::string>());
                request_count_client++;
            }

            // 4. Test DELETE method with 204 code
            {
                std::cout << "Client: Sending DELETE request to /test/456" << std::endl;
                qb::http::Request request{HTTP_DELETE, {"http://localhost:9877/test/456"}};

                auto response = qb::http::DELETE(request);

                std::cout << "Client: Received DELETE response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_NO_CONTENT, response.status_code);
                EXPECT_TRUE(response.body().empty());
                request_count_client++;
            }
            
            // 5. Test query parameters
            {
                std::cout << "Client: Sending GET request with query parameters" << std::endl;
                qb::http::Request request{{"http://localhost:9877/query?name=test&age=25&sort=asc"}};

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
                qb::http::Request request{{"http://localhost:9877/error"}};
                
                auto response = qb::http::GET(request, 5.0);
                
                std::cout << "Client: Received ERROR response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_INTERNAL_SERVER_ERROR, response.status_code);
                EXPECT_EQ("Intentional error", response.body().as<std::string>());
                request_count_client++;
            }
            
            // 7. Test sync route without explicit complete
            {
                std::cout << "Client: Sending GET request to /sync-no-complete" << std::endl;
                qb::http::Request request{{"http://localhost:9877/sync-no-complete"}};
                
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
                qb::http::Request request{{"http://localhost:9877/async"}};
                
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
                qb::http::Request request{{"http://localhost:9877/api/v1/status"}};
                
                auto response = qb::http::GET(request);
                
                std::cout << "Client: Received group route response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("API Status: OK", response.body().as<std::string>());
                EXPECT_EQ("group", response.header("X-Route-Type"));
                request_count_client++;
            }
            
            // 10. Test Cookie Setting
            {
                std::cout << "Client: Testing cookie setting" << std::endl;
                qb::http::Request request{{"http://localhost:9877/cookie-set"}};
                
                auto response = qb::http::GET(request);
                
                std::cout << "Client: Received cookie-set response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("Cookie has been set", response.body().as<std::string>());
                
                // Check the cookie values
                EXPECT_TRUE(response.cookie("test_cookie") != nullptr);
                EXPECT_EQ("cookie_value", response.cookie("test_cookie")->value());
                
                EXPECT_TRUE(response.cookie("test_cookie_with_attrs") != nullptr);
                EXPECT_EQ("value_with_attrs", response.cookie("test_cookie_with_attrs")->value());
                EXPECT_EQ("/", response.cookie("test_cookie_with_attrs")->path());
                EXPECT_TRUE(response.cookie("test_cookie_with_attrs")->http_only());
                EXPECT_EQ(3600, *(response.cookie("test_cookie_with_attrs")->max_age()));
                
                request_count_client++;
            }
            
            // 11. Test Cookie Reading
            {
                std::cout << "Client: Testing cookie reading" << std::endl;
                qb::http::Request request{{"http://localhost:9877/cookie-read"}};
                
                // Add the cookie to the request
                request.add_header("Cookie", "test_cookie=cookie_value");
                
                auto response = qb::http::GET(request);
                
                std::cout << "Client: Received cookie-read response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("Cookie value: cookie_value", response.body().as<std::string>());
                
                request_count_client++;
            }
            
            // 12. Test JSON Content Type
            {
                std::cout << "Client: Testing JSON response" << std::endl;
                qb::http::Request request{{"http://localhost:9877/json"}};
                
                auto response = qb::http::GET(request);
                
                std::cout << "Client: Received JSON response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("application/json", response.header("Content-Type"));
                
                // Parse and verify JSON
                auto json_body = response.body().as<qb::json>();
                EXPECT_EQ("This is JSON", json_body["message"]);
                EXPECT_EQ(true, json_body["success"]);
                EXPECT_EQ(200, json_body["code"]);
                
                request_count_client++;
            }
            
            // 13. Test Request Headers Echo
            {
                std::cout << "Client: Testing headers echo" << std::endl;
                qb::http::Request request{{"http://localhost:9877/echo-headers"}};
                
                // Add a custom header for testing
                request.add_header("X-Custom-Header", "test-value");
                request.add_header("User-Agent", "Echo-Headers-Test/1.0");
                
                auto response = qb::http::GET(request);
                
                std::cout << "Client: Received headers echo response status: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("application/json", response.header("Content-Type"));
                
                // Parse and verify JSON in the headers echo test
                auto headers_json_body = response.body().as<qb::json>();
                EXPECT_TRUE(headers_json_body.contains("x-custom-header") ||
                           headers_json_body.contains("X-Custom-Header"));
                EXPECT_TRUE(headers_json_body.contains("user-agent") ||
                           headers_json_body.contains("User-Agent"));
                
                request_count_client++;
            }
            
            // Test the new advanced routes
            
            // 14. Public route test (no auth required)
            {
                std::cout << "Client: Testing public route" << std::endl;
                qb::http::Request request{{"http://localhost:9877/public/info"}};
                
                auto response = qb::http::GET(request);
                
                std::cout << "Client: Received public info response: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("Public API information", response.body().as<std::string>());
                request_count_client++;
            }
            
            // 15. Protected route without auth (should fail)
            {
                std::cout << "Client: Testing protected route without auth" << std::endl;
                qb::http::Request request{{"http://localhost:9877/protected/profile"}};
                
                auto response = qb::http::GET(request);
                
                std::cout << "Client: Received protected response (no auth): " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_UNAUTHORIZED, response.status_code);
                EXPECT_EQ("Authentication required", response.body().as<std::string>());
                request_count_client++;
            }
            
            // 16. Protected route with valid auth (should succeed)
            {
                std::cout << "Client: Testing protected route with valid auth" << std::endl;
                qb::http::Request request{{"http://localhost:9877/protected/profile"}};
                request.add_header("Authorization", "Bearer valid-token");
                
                auto response = qb::http::GET(request);
                
                std::cout << "Client: Received protected response (with auth): " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("application/json", response.header("Content-Type"));
                
                auto json_body = response.body().as<qb::json>();
                EXPECT_EQ("test-user-123", json_body["user_id"]);
                EXPECT_EQ(true, json_body["is_admin"]);
                request_count_client++;
            }
            
            // 17. Rate-limited route (first 3 requests should succeed, 4th should fail)
            {
                std::cout << "Client: Testing rate-limited route" << std::endl;
                
                // Use the same IP for all requests
                std::string client_ip = "192.168.1.123";
                
                // First 3 requests should succeed
                for (int i = 0; i < 3; i++) {
                    qb::http::Request request{{"http://localhost:9877/rate-limited/resource"}};
                    request.add_header("X-Client-IP", client_ip);
                    
                    auto response = qb::http::GET(request);
                    
                    EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                    EXPECT_EQ("Rate-limited resource accessed successfully", response.body().as<std::string>());
                }
                
                // 4th request should fail due to rate limit
                {
                    qb::http::Request request{{"http://localhost:9877/rate-limited/resource"}};
                    request.add_header("X-Client-IP", client_ip);
                    
                    auto response = qb::http::GET(request);
                    
                    std::cout << "Client: Received rate-limited response: " << response.status_code << std::endl;
                    EXPECT_EQ(HTTP_STATUS_TOO_MANY_REQUESTS, response.status_code);
                    EXPECT_EQ("Rate limit exceeded", response.body().as<std::string>());
                }
                
                request_count_client++; // Count this as one test case
            }
            
            // 18. Async route with delay
            {
                std::cout << "Client: Testing async route with delay" << std::endl;
                qb::http::Request request{{"http://localhost:9877/async/delay/300"}};
                
                auto start_time = std::chrono::steady_clock::now();
                auto response = qb::http::GET(request, 5.0); // Longer timeout for async
                auto end_time = std::chrono::steady_clock::now();
                
                auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    end_time - start_time).count();
                
                std::cout << "Client: Received delayed response: " << response.status_code << std::endl;
                EXPECT_EQ(HTTP_STATUS_OK, response.status_code);
                EXPECT_EQ("Delayed response after 300ms", response.body().as<std::string>());
                EXPECT_GE(duration_ms, 300); // Should take at least the delay time
                request_count_client++;
            }
            
            std::cout << "Client thread completed, processed " << request_count_client << " tests" << std::endl;
            
        } catch (const std::exception& e) {
            std::cout << "Client exception: " << e.what() << std::endl;
            FAIL() << "Client test exception: " << e.what();
        }
    });
    
    // Wait for threads to complete
    client_thread.join();
    server_thread.join();
    
    // Verify all tests were executed
    EXPECT_EQ(18, request_count_client.load());
    EXPECT_EQ(19, request_count_server.load());
    
    // Verify server-side assertions
    EXPECT_EQ(expected_server_assertions, server_side_assertions.load());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
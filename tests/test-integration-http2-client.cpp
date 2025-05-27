#include <gtest/gtest.h>
#include "../2/client.h"
#include "../2/http2.h"
#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>
#include <fstream>

// Counters to track request processing
std::atomic<int> h2_request_count_server{0};
std::atomic<int> h2_request_count_client{0};
std::atomic<bool> h2_server_ready{false};

// Test assertion counters for server-side validation
std::atomic<int> h2_server_side_assertions{0};
std::atomic<int> h2_expected_server_assertions{0};

// Helper to give a bit of time for server to process, if needed.
void h2_short_sleep_for_server_processing() {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// Forward declaration
class Http2IntegrationServer;

// HTTP/2 session class that handles client connections
class Http2IntegrationSession : public qb::http2::use<Http2IntegrationSession>::session<Http2IntegrationServer> {
public:
    Http2IntegrationSession(Http2IntegrationServer &server_ref)
        : session(server_ref) {
    }
};

// HTTP/2 server that listens for connections and configures routes
class Http2IntegrationServer : public qb::http2::use<Http2IntegrationServer>::server<Http2IntegrationSession> {
public:
    Http2IntegrationServer()
        : qb::http2::use<Http2IntegrationServer>::server<Http2IntegrationSession>() {
        
        std::cout << "Setting up HTTP/2 routes in the server..." << std::endl;

        // 1. Basic GET route
        router().get("/api/test", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "HTTP/2 GET Success";
            ctx->response().add_header("X-Protocol", "HTTP/2");
            h2_request_count_server++;
            ctx->complete();
        });

        // 2. POST route with JSON data
        router().post("/api/data", [](auto ctx) {
            ctx->response().status() = qb::http::status::CREATED;
            
            std::string request_body = ctx->request().body().template as<std::string>();
            std::string response_body = "Data received: " + request_body + " - created successfully";
            
            ctx->response().body() = response_body;
            ctx->response().add_header("Content-Type", "application/json");
            ctx->response().add_header("X-Protocol", "HTTP/2");
            h2_request_count_server++;

            if (request_body.find("test_data") != std::string::npos) {
                h2_server_side_assertions++;
            }
            ctx->complete();
        });

        // 3. Route with path parameter
        router().get("/api/users/:id", [](auto ctx) {
            std::string id = ctx->path_param("id");
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "User ID: " + id + " (via HTTP/2)";
            ctx->response().add_header("X-Protocol", "HTTP/2");
            h2_request_count_server++;

            if (id == "100" || id == "101" || id == "102" || id == "200" || id == "201" || id == "202") {
                h2_server_side_assertions++;
            }
            ctx->complete();
        });

        // 4. Large response route
        router().get("/api/large", [](auto ctx) {
            std::string large_body;
            large_body.reserve(10000);
            for (int i = 0; i < 1000; ++i) {
                large_body += "This is line " + std::to_string(i) + " of a large HTTP/2 response.\n";
            }
            
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = large_body;
            ctx->response().add_header("Content-Type", "text/plain");
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->response().add_header("Content-Length", std::to_string(large_body.length()));
            h2_request_count_server++;
            ctx->complete();
        });

        // 5. Error route
        router().get("/api/error", [](auto ctx) {
            ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
            ctx->response().body() = "HTTP/2 server error occurred";
            ctx->response().add_header("X-Protocol", "HTTP/2");
            h2_request_count_server++;
            ctx->complete();
        });
    }
};

class Http2ClientIntegrationTest : public ::testing::Test {
protected:
    std::unique_ptr<Http2IntegrationServer> _server;
    std::thread _server_thread;
    static const int SERVER_PORT = 9877; // Different port from HTTP/1.1 tests
    const char* CERT_FILE = "cert.pem"; 
    const char* KEY_FILE  = "key.pem";

    bool check_test_certs_exist() {
        std::ifstream certf(CERT_FILE);
        std::ifstream keyf(KEY_FILE);
        bool cert_exists = certf.good();
        bool key_exists = keyf.good();
        if (!cert_exists) std::cerr << "Warning: Test certificate file not found: " << CERT_FILE << std::endl;
        if (!key_exists) std::cerr << "Warning: Test key file not found: " << KEY_FILE << std::endl;
        return cert_exists && key_exists;
    }

public:
    void SetUp() override {
        if (!check_test_certs_exist()) {
            GTEST_SKIP() << "Test SSL certificates (" << CERT_FILE << ", " << KEY_FILE << ") not found, skipping HTTP/2 client tests.";
            return;
        }

        qb::io::async::init(); // Ensure async is init for the main test thread

        // Reset counters for each test
        h2_request_count_server = 0;
        h2_request_count_client = 0;
        h2_server_side_assertions = 0;
        h2_expected_server_assertions = 0;
        h2_server_ready = false;

        _server = std::make_unique<Http2IntegrationServer>();

        _server_thread = std::thread([this]() {
            qb::io::async::init(); // Init for server thread

            // Initialize SSL context for HTTP/2
            _server->transport().init(qb::io::ssl::create_server_context(SSLv23_server_method(), "cert.pem", "key.pem"));
            _server->transport().set_supported_alpn_protocols({"h2", "http/1.1"});
            
            // Listen and start
            _server->transport().listen_v4(SERVER_PORT);
            _server->start();

            h2_server_ready = true;
            std::cout << "HTTP/2 Server is ready and listening at port " << SERVER_PORT << std::endl;

            // Keep server running as long as h2_server_ready is true
            while (h2_server_ready.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
            std::cout << "HTTP/2 Server thread shutting down." << std::endl;
        });

        // Wait for the server to be ready
        while (!h2_server_ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        // Give extra time for SSL initialization
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    void TearDown() override {
        if (IsSkipped()) return;
        if (h2_server_ready.load(std::memory_order_acquire)) {
            h2_server_ready.store(false, std::memory_order_release);
            if (_server_thread.joinable()) {
                _server_thread.join();
            }
        }
    }

    template<typename Func>
    void MakeHttp2ClientRequest(Func &&client_logic, int expected_server_req_increment = 1,
                               int expected_server_assert_increment = 0) {
        int initial_server_requests = h2_request_count_server.load();
        int initial_server_assertions = h2_server_side_assertions.load();
        h2_expected_server_assertions = expected_server_assert_increment;

        qb::io::async::init();

        client_logic();

        // Process events for a reasonable time to allow completion
        auto start_time = std::chrono::steady_clock::now();
        auto max_duration = std::chrono::seconds(1);

        while (std::chrono::steady_clock::now() - start_time < max_duration) {
            qb::io::async::run(EVRUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        h2_short_sleep_for_server_processing();

        EXPECT_EQ(h2_request_count_server.load(), initial_server_requests + expected_server_req_increment);
        EXPECT_EQ(h2_server_side_assertions.load(), initial_server_assertions + expected_server_assert_increment);
    }
};

TEST_F(Http2ClientIntegrationTest, SimpleGetRequest) {
    if (IsSkipped()) return;
    MakeHttp2ClientRequest([&]() {
        std::atomic<bool> response_received{false};
        qb::http::Response received_response;
        int h2_request_count_client_local = 0;

        auto client = qb::http2::make_client("https://localhost:" + std::to_string(SERVER_PORT));
        client->set_connect_timeout(15.0);

        std::atomic<bool> connect_cb_called{false};
        std::atomic<bool> connected_successfully{false};
        std::string connection_error_msg;

        client->connect([&](bool connected, const std::string& err_msg){
            connect_cb_called = true;
            if (connected) {
                connected_successfully = true;
            } else {
                connection_error_msg = err_msg;
                connected_successfully = false;
            }
        });

        auto connect_start_time = std::chrono::steady_clock::now();
        while(!connect_cb_called.load(std::memory_order_acquire) &&
              std::chrono::steady_clock::now() - connect_start_time < std::chrono::seconds(10)) {
            qb::io::async::run(EVRUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        ASSERT_TRUE(connect_cb_called.load(std::memory_order_acquire)) << "HTTP/2 client connect callback not invoked within timeout.";
        ASSERT_TRUE(connected_successfully.load(std::memory_order_acquire)) << "HTTP/2 client connection failed: " << connection_error_msg;

        qb::http::Request request;
        request.method() = qb::http::Method::GET;
        request.uri() = qb::io::uri("/api/test");

        client->push_request(request, [&](qb::http::Response response) {
            received_response = response;
            response_received = true;
            
            EXPECT_EQ(response.status(), qb::http::status::OK);
            EXPECT_EQ(response.body().template as<std::string>(), "HTTP/2 GET Success");
            EXPECT_TRUE(response.has_header("X-Protocol"));
            EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
            
            h2_request_count_client_local++;
        });

        // Wait for response (connect is already called and waited for)
        auto response_start_time = std::chrono::steady_clock::now();
        while (!response_received.load(std::memory_order_acquire) && 
               std::chrono::steady_clock::now() - response_start_time < std::chrono::seconds(10)) {
            qb::io::async::run(EVRUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        ASSERT_TRUE(response_received.load(std::memory_order_acquire)) << "Client did not receive response for SimpleGetRequest within timeout.";
        EXPECT_EQ(h2_request_count_client_local, 1);
        h2_request_count_client += h2_request_count_client_local;
    }, 1, 0);
}

TEST_F(Http2ClientIntegrationTest, PostRequestWithData) {
    MakeHttp2ClientRequest([&]() {
        std::atomic<bool> response_received{false};
        qb::http::Response received_response;

        auto client = qb::http2::make_client("https://localhost:" + std::to_string(SERVER_PORT));
        client->set_connect_timeout(15.0);

        qb::http::Request request;
        request.method() = qb::http::Method::POST;
        request.uri() = qb::io::uri("/api/data");
        request.add_header("Content-Type", "application/json");
        request.body() = R"({"key": "test_data", "value": 123})";

        client->push_request(request, [&](qb::http::Response response) {
            received_response = response;
            response_received = true;
            
            EXPECT_EQ(response.status(), qb::http::status::CREATED);
            EXPECT_TRUE(response.body().template as<std::string>().find("test_data") != std::string::npos);
            EXPECT_TRUE(response.has_header("X-Protocol"));
            EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
        });

        client->connect();

        auto response_start_time = std::chrono::steady_clock::now();
        while (!response_received.load(std::memory_order_acquire) && 
               std::chrono::steady_clock::now() - response_start_time < std::chrono::seconds(10)) {
            qb::io::async::run(EVRUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        ASSERT_TRUE(response_received.load(std::memory_order_acquire)) << "Client did not receive response for PostRequestWithData within timeout.";
    }, 1, 1);
}

TEST_F(Http2ClientIntegrationTest, ConcurrentRequests) {
    MakeHttp2ClientRequest([&]() {
        std::atomic<int> responses_received{0};
        std::vector<qb::http::Response> received_responses(3);

        auto client = qb::http2::make_client("https://localhost:" + std::to_string(SERVER_PORT));
        client->set_connect_timeout(15.0);

        // Send 3 concurrent requests
        for (int i = 0; i < 3; ++i) {
            qb::http::Request request;
            request.method() = qb::http::Method::GET;
            request.uri() = qb::io::uri("/api/users/" + std::to_string(100 + i));

            client->push_request(request, [&, i](qb::http::Response response) {
                received_responses[i] = response;
                responses_received++;
                
                EXPECT_EQ(response.status(), qb::http::status::OK);
                EXPECT_TRUE(response.body().template as<std::string>().find(std::to_string(100 + i)) != std::string::npos);
                EXPECT_TRUE(response.has_header("X-Protocol"));
                EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
            });
        }

        client->connect();

        auto response_start_time = std::chrono::steady_clock::now();
        while (responses_received.load(std::memory_order_acquire) < 3 && 
               std::chrono::steady_clock::now() - response_start_time < std::chrono::seconds(10)) {
            qb::io::async::run(EVRUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        ASSERT_EQ(responses_received.load(std::memory_order_acquire), 3) << "Client did not receive all responses for ConcurrentRequests within timeout.";
    }, 3, 3);
}

TEST_F(Http2ClientIntegrationTest, BatchRequests) {
    MakeHttp2ClientRequest([&]() {
        std::atomic<bool> batch_completed{false};
        std::vector<qb::http::Response> batch_responses;

        auto client = qb::http2::make_client("https://localhost:" + std::to_string(SERVER_PORT));
        client->set_connect_timeout(15.0);

        std::vector<qb::http::Request> requests;
        for (int i = 0; i < 3; ++i) {
            qb::http::Request request;
            request.method() = qb::http::Method::GET;
            request.uri() = qb::io::uri("/api/users/" + std::to_string(200 + i));
            requests.push_back(std::move(request));
        }

        client->push_requests(requests, [&](std::vector<qb::http::Response> responses) {
            batch_responses = std::move(responses);
            batch_completed = true;
            
            EXPECT_EQ(batch_responses.size(), 3);
            for (size_t i = 0; i < batch_responses.size(); ++i) {
                EXPECT_EQ(batch_responses[i].status(), qb::http::status::OK);
                EXPECT_TRUE(batch_responses[i].body().template as<std::string>().find(std::to_string(200 + i)) != std::string::npos);
                EXPECT_TRUE(batch_responses[i].has_header("X-Protocol"));
                EXPECT_EQ(batch_responses[i].header("X-Protocol"), "HTTP/2");
            }
        });

        client->connect();

        auto response_start_time = std::chrono::steady_clock::now();
        while (!batch_completed.load(std::memory_order_acquire) && 
               std::chrono::steady_clock::now() - response_start_time < std::chrono::seconds(10)) {
            qb::io::async::run(EVRUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        ASSERT_TRUE(batch_completed.load(std::memory_order_acquire)) << "Client did not complete batch request within timeout.";
    }, 3, 3);
}

TEST_F(Http2ClientIntegrationTest, ErrorHandling) {
    MakeHttp2ClientRequest([&]() {
        std::atomic<bool> response_received{false};
        qb::http::Response received_response;

        auto client = qb::http2::make_client("https://localhost:" + std::to_string(SERVER_PORT));
        client->set_connect_timeout(15.0);

        qb::http::Request request;
        request.method() = qb::http::Method::GET;
        request.uri() = qb::io::uri("/api/error");

        client->push_request(request, [&](qb::http::Response response) {
            received_response = response;
            response_received = true;
            
            EXPECT_EQ(response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
            EXPECT_TRUE(response.body().template as<std::string>().find("server error") != std::string::npos);
            EXPECT_TRUE(response.has_header("X-Protocol"));
            EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
        });

        client->connect();

        auto response_start_time = std::chrono::steady_clock::now();
        while (!response_received.load(std::memory_order_acquire) && 
               std::chrono::steady_clock::now() - response_start_time < std::chrono::seconds(10)) {
            qb::io::async::run(EVRUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        ASSERT_TRUE(response_received.load(std::memory_order_acquire)) << "Client did not receive response for ErrorHandling within timeout.";
    }, 1, 0);
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
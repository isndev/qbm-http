#include <gtest/gtest.h>
#include <qb/io/async.h>
#include <qb/io/uri.h> // For qb::http::Request constructor
#include "../http.h" // Brings in make_server, AppServer, DefaultSession, etc.
#include "../2/http2.h" // For HTTP/2 server components
#include "../2/client.h" // For HTTP/2 client

#if QB_HAS_SSL
#include <fstream>     // For checking certificate file existence
#endif

#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>    // For std::unique_ptr
#include <string>
#include <vector>

// --- Test Counters & Flags ---
static std::atomic<bool> g_make_server_test_server_ready{false};
static std::atomic<int> g_make_server_test_req_count_server{0};
static std::atomic<int> g_make_server_test_req_count_client{0};

// Helper to get current test name for logging
static std::string GetCurrentTestNameForMakeServer() {
    const auto *current_test_info = ::testing::UnitTest::GetInstance()->current_test_info();
    if (current_test_info) {
        return std::string(current_test_info->test_suite_name()) + "." + current_test_info->name();
    }
    return "UNKNOWN_TEST.UNKNOWN_CASE";
}


// --- Test Fixture for qb::http::make_server (default session) ---
class HttpMakeServerTest : public ::testing::Test {
protected:
    std::unique_ptr<qb::http::Server<>> server_instance;
    std::thread server_thread;
    const uint16_t TEST_PORT = 9878;

    void SetUp() override {
        qb::io::async::init(); 

        g_make_server_test_server_ready = false;
        g_make_server_test_req_count_server = 0;
        g_make_server_test_req_count_client = 0;

        server_instance = qb::http::make_server(); 

        server_instance->router().get("/ping", [](std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) {
            g_make_server_test_req_count_server++;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "pong_http_default";
            ctx->complete();
        });
        server_instance->router().compile();

        server_thread = std::thread([this]() {
            qb::io::async::init(); 
            server_instance->transport().listen_v4(TEST_PORT);
            server_instance->start();
            g_make_server_test_server_ready = true;
            std::cout << "[" << GetCurrentTestNameForMakeServer() << "] HTTP Server (default session) ready on port " << TEST_PORT << std::endl;
            while (g_make_server_test_server_ready.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
            std::cout << "[" << GetCurrentTestNameForMakeServer() << "] HTTP Server (default session) thread finishing." << std::endl;
        });

        while (!g_make_server_test_server_ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
         std::this_thread::sleep_for(std::chrono::milliseconds(200)); 
    }

    void TearDown() override {
        g_make_server_test_server_ready = false;
        if (server_thread.joinable()) {
            server_thread.join();
        }
        server_instance.reset(); 
        std::cout << "[" << GetCurrentTestNameForMakeServer() << "] Test Finished. Client Reqs: " << g_make_server_test_req_count_client << ", Server Reqs: " << g_make_server_test_req_count_server << std::endl;

    }
};

TEST_F(HttpMakeServerTest, PingDefaultSessionHttpServer) {
    std::cout << "[" << GetCurrentTestNameForMakeServer() << "] Client: Sending GET /ping to HTTP server (default session) on port " << TEST_PORT << std::endl;
    qb::http::Request request{{"http://localhost:" + std::to_string(TEST_PORT) + "/ping"}};
    auto response = qb::http::GET(request);

    EXPECT_EQ(HTTP_STATUS_OK, response.status());
    EXPECT_EQ("pong_http_default", response.body().as<std::string>());
    g_make_server_test_req_count_client++;

    EXPECT_EQ(1, g_make_server_test_req_count_client.load());
    EXPECT_EQ(1, g_make_server_test_req_count_server.load());
}

#if QB_HAS_SSL

// --- Test Fixture for qb::http::ssl::make_server (default session) ---
class HttpsMakeServerTest : public ::testing::Test {
protected:
    std::unique_ptr<qb::http::ssl::Server<>> server_instance;
    std::thread server_thread;
    const uint16_t TEST_PORT_SSL = 9880; 
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


    void SetUp() override {
        if (!check_test_certs_exist()) {
            GTEST_SKIP() << "Test SSL certificates (" << CERT_FILE << ", " << KEY_FILE << ") not found, skipping HTTPS tests.";
            return;
        }

        qb::io::async::init();
        g_make_server_test_server_ready = false;
        g_make_server_test_req_count_server = 0;
        g_make_server_test_req_count_client = 0;

        server_instance = qb::http::ssl::make_server(); 

        auto ssl_ctx = qb::io::ssl::create_server_context(TLS_server_method(), CERT_FILE, KEY_FILE);
        if (!ssl_ctx) {
             throw std::runtime_error("Failed to create SSL server context for test.");
        }
        server_instance->transport().init(std::move(ssl_ctx));

        server_instance->router().get("/ping_ssl", [](std::shared_ptr<qb::http::Context<qb::http::ssl::DefaultSecureSession>> ctx) {
            g_make_server_test_req_count_server++;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "pong_https_default";
            ctx->complete();
        });
        server_instance->router().compile();

        server_thread = std::thread([this]() {
            qb::io::async::init();
            server_instance->transport().listen_v4(TEST_PORT_SSL);
            server_instance->start();
            g_make_server_test_server_ready = true;
            std::cout << "[" << GetCurrentTestNameForMakeServer() << "] HTTPS Server (default session) ready on port " << TEST_PORT_SSL << std::endl;
            while (g_make_server_test_server_ready.load(std::memory_order_acquire)) {
                 if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
            std::cout << "[" << GetCurrentTestNameForMakeServer() << "] HTTPS Server (default session) thread finishing." << std::endl;
        });

        while (!g_make_server_test_server_ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
         std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    void TearDown() override {
        if (IsSkipped()) return; 
        g_make_server_test_server_ready = false;
        if (server_thread.joinable()) {
            server_thread.join();
        }
        server_instance.reset();
         std::cout << "[" << GetCurrentTestNameForMakeServer() << "] Test Finished. Client Reqs: " << g_make_server_test_req_count_client << ", Server Reqs: " << g_make_server_test_req_count_server << std::endl;
    }
};

TEST_F(HttpsMakeServerTest, PingDefaultSessionHttpsServer) {
    if (IsSkipped()) return;
    std::cout << "[" << GetCurrentTestNameForMakeServer() << "] Client: Sending GET /ping_ssl to HTTPS server (default session) on port " << TEST_PORT_SSL << std::endl;
    qb::http::Request request{{"https://localhost:" + std::to_string(TEST_PORT_SSL) + "/ping_ssl"}};
    
    auto response = qb::http::GET(request); 

    EXPECT_EQ(HTTP_STATUS_OK, response.status());
    EXPECT_EQ("pong_https_default", response.body().as<std::string>());
    g_make_server_test_req_count_client++;

    EXPECT_EQ(1, g_make_server_test_req_count_client.load());
    EXPECT_EQ(1, g_make_server_test_req_count_server.load());
}

#endif // QB_HAS_SSL

#if QB_HAS_SSL
// --- Test Fixture for qb::http2::make_server --- 
class Http2MakeServerTest : public ::testing::Test {
protected:
    std::unique_ptr<qb::http2::Server<>> server_instance_h2;
    std::thread server_thread_h2;
    const uint16_t TEST_PORT_HTTP2 = 9882;
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

    void SetUp() override {
        if (!check_test_certs_exist()) {
            GTEST_SKIP() << "Test SSL certificates (" << CERT_FILE << ", " << KEY_FILE << ") not found, skipping HTTP/2 tests.";
            return;
        }

        qb::io::async::init(); 
        g_make_server_test_server_ready = false;
        g_make_server_test_req_count_server = 0;
        g_make_server_test_req_count_client = 0;

        server_instance_h2 = qb::http2::make_server(); 

        auto ssl_ctx_h2 = qb::io::ssl::create_server_context(TLS_server_method(), CERT_FILE, KEY_FILE);
        if (!ssl_ctx_h2) {
             throw std::runtime_error("Failed to create SSL server context for HTTP/2 test.");
        }
        server_instance_h2->transport().init(std::move(ssl_ctx_h2)); 
        server_instance_h2->transport().set_supported_alpn_protocols({"h2", "http/1.1"});

        server_instance_h2->router().get("/ping_http2", [](std::shared_ptr<qb::http::Context<qb::http2::DefaultSession>> ctx) {
            g_make_server_test_req_count_server++;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "pong_http2_default";
            ctx->complete();
        });
        server_instance_h2->router().compile();

        server_thread_h2 = std::thread([this]() {
            qb::io::async::init(); 
            server_instance_h2->transport().listen_v4(TEST_PORT_HTTP2);
            server_instance_h2->start();
            g_make_server_test_server_ready = true;
            std::cout << "[" << GetCurrentTestNameForMakeServer() << "] HTTP/2 Server ready on port " << TEST_PORT_HTTP2 << std::endl;
            while (g_make_server_test_server_ready.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
            std::cout << "[" << GetCurrentTestNameForMakeServer() << "] HTTP/2 Server thread finishing." << std::endl;
        });

        while (!g_make_server_test_server_ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
         std::this_thread::sleep_for(std::chrono::milliseconds(200)); 
    }

    void TearDown() override {
        if (IsSkipped()) return; 
        g_make_server_test_server_ready = false;
        if (server_thread_h2.joinable()) {
            server_thread_h2.join();
        }
        server_instance_h2.reset(); 
        std::cout << "[" << GetCurrentTestNameForMakeServer() << "] HTTP/2 Test Finished. Client Reqs: " << g_make_server_test_req_count_client << ", Server Reqs: " << g_make_server_test_req_count_server << std::endl;
    }
};

TEST_F(Http2MakeServerTest, PingHttp2Server) {
    if (IsSkipped()) return;
    std::cout << "[" << GetCurrentTestNameForMakeServer() << "] Client: Sending GET /ping_http2 to HTTP/2 server on port " << TEST_PORT_HTTP2 << std::endl;
    
    std::string target_uri = "https://localhost:" + std::to_string(TEST_PORT_HTTP2);
    auto h2_client = std::make_shared<qb::http2::Client>(target_uri);

    std::atomic<bool> connect_successful{false};
    std::atomic<bool> connect_attempted{false}; // To know if callback was even called
    std::string connection_error_msg;

    std::atomic<bool> response_received{false};
    qb::http::Response actual_response;

    h2_client->connect([&](bool connected, const std::string& err_msg) {
        connect_attempted = true;
        if (connected) {
            std::cout << "[Http2MakeServerTest.PingHttp2Server] Client connected to " << target_uri << std::endl;
            connect_successful = true;
        } else {
            std::cerr << "[Http2MakeServerTest.PingHttp2Server] Client connection failed: " << err_msg << std::endl;
            connect_successful = false;
            connection_error_msg = err_msg;
        }
    });

    // Loop to wait for connection
    auto connect_start_time = std::chrono::steady_clock::now();
    while (!connect_attempted.load(std::memory_order_acquire) && 
           std::chrono::steady_clock::now() - connect_start_time < std::chrono::seconds(10)) {
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(connect_attempted.load()) << "HTTP/2 Client connect callback was not invoked.";
    ASSERT_TRUE(connect_successful.load()) << "HTTP/2 Client failed to connect: " << connection_error_msg;
    
    qb::http::Request request{{target_uri + "/ping_http2"}};
    request.method() = qb::http::Method::GET; 

    bool pushed = h2_client->push_request(std::move(request), 
        [&](qb::http::Response resp) {
            std::cout << "[Http2MakeServerTest.PingHttp2Server] Client received response. Status: " << resp.status() << std::endl;
            actual_response = std::move(resp);
            response_received = true;
        }
    );
    ASSERT_TRUE(pushed) << "HTTP/2 Client failed to push request.";

    // Loop to wait for response
    auto response_start_time = std::chrono::steady_clock::now();
    while (!response_received.load(std::memory_order_acquire) && 
           std::chrono::steady_clock::now() - response_start_time < std::chrono::seconds(10)) {
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(response_received.load()) << "HTTP/2 Client did not receive response within timeout.";

    EXPECT_EQ(HTTP_STATUS_OK, actual_response.status());
    EXPECT_EQ("pong_http2_default", actual_response.body().as<std::string>());
    g_make_server_test_req_count_client++;

    EXPECT_EQ(1, g_make_server_test_req_count_client.load());
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Give server a bit more time to increment its counter
    EXPECT_EQ(1, g_make_server_test_req_count_server.load());

    h2_client->disconnect();
}

#endif // QB_HAS_SSL
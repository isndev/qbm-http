#include <gtest/gtest.h>
#include "../http.h"
#include "../request.h" 
#include "../response.h"
#include "../routing/router.h"
#include "../routing/context.h"
#include "../routing/types.h"
#include "../middleware/logging.h" // The adapted LoggingMiddleware
#include "../routing/middleware.h" // For MiddlewareTask if needed

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <sstream>

// --- Mock Session for LoggingMiddleware Tests ---
struct MockLoggingSession {
    qb::http::Response _response;
    std::string _session_id_str = "logging_test_session";
    std::vector<std::pair<qb::http::LogLevel, std::string>> _log_entries;
    bool _final_handler_called = false;

    qb::http::Response& get_response_ref() { return _response; }

    MockLoggingSession& operator<<(const qb::http::Response& resp) {
        _response = resp;
        return *this;
    }

    void reset() {
        _response = qb::http::Response();
        _log_entries.clear();
        _final_handler_called = false;
    }

    void add_log_entry(qb::http::LogLevel level, const std::string& message) {
        _log_entries.push_back({level, message});
    }
};

// --- Test Fixture for LoggingMiddleware --- 
class LoggingMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockLoggingSession> _session;
    std::unique_ptr<qb::http::Router<MockLoggingSession>> _router;
    // TaskExecutor not needed as LoggingMiddleware and its hooks are synchronous in nature for logging.

    // The LogFunction for tests will append to _session->_log_entries
    qb::http::LoggingMiddleware<MockLoggingSession>::LogFunction _test_logger_func;

    void SetUp() override {
        _session = std::make_shared<MockLoggingSession>();
        _router = std::make_unique<qb::http::Router<MockLoggingSession>>();
        _test_logger_func = [this](qb::http::LogLevel level, const std::string& message) {
            if (_session) {
                _session->add_log_entry(level, message);
            }
        };
    }

    qb::http::Request create_request(qb::http::method method_val = qb::http::method::HTTP_GET, 
                                     const std::string& target_path = "/log_test",
                                     const std::string& query_params = "") {
        qb::http::Request req;
        req.method = method_val;
        std::string full_path = target_path;
        if (!query_params.empty()) {
            full_path += "?" + query_params;
        }
        try {
            req.uri() = qb::io::uri(full_path);
        } catch (const std::exception& e) {
            ADD_FAILURE() << "URI parse failure: " << full_path << " (" << e.what() << ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        return req;
    }

    qb::http::RouteHandlerFn<MockLoggingSession> basic_handler(qb::http::status status_to_return = qb::http::status::HTTP_STATUS_OK) {
        return [this, status_to_return](std::shared_ptr<qb::http::Context<MockLoggingSession>> ctx) {
            if(_session) _session->_final_handler_called = true;
            ctx->response().status_code = status_to_return;
            ctx->response().body() = "HandlerResponse";
            ctx->complete();
        };
    }

    void configure_router_and_run(std::shared_ptr<qb::http::LoggingMiddleware<MockLoggingSession>> logging_mw, 
                                  qb::http::Request request, 
                                  qb::http::status handler_status = qb::http::status::HTTP_STATUS_OK) {
        _router->use(logging_mw);
        _router->get("/log_test", basic_handler(handler_status));
        _router->post("/log_test", basic_handler(handler_status)); // Add for different methods
        _router->compile();
        
        _session->reset();
        _router->route(_session, std::move(request));
        // Lifecycle hooks for response logging will be triggered by the router's processing.
    }
};

// --- Test Cases --- 

TEST_F(LoggingMiddlewareTest, BasicRequestAndResponseLogging) {
    auto logging_mw = qb::http::logging_middleware<MockLoggingSession>(_test_logger_func);
    configure_router_and_run(logging_mw, create_request(qb::http::method::HTTP_GET, "/log_test"));

    ASSERT_EQ(_session->_log_entries.size(), 2);
    EXPECT_EQ(_session->_log_entries[0].first, qb::http::LogLevel::Info); // Default request level
    EXPECT_NE(_session->_log_entries[0].second.find("Request: GET /log_test"), std::string::npos);
    
    EXPECT_EQ(_session->_log_entries[1].first, qb::http::LogLevel::Debug); // Default response level
    EXPECT_NE(_session->_log_entries[1].second.find("Response: 200"), std::string::npos); // Assuming 200 OK from basic_handler
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(LoggingMiddlewareTest, CustomLogLevels) {
    auto logging_mw = qb::http::logging_middleware<MockLoggingSession>(
        _test_logger_func, 
        qb::http::LogLevel::Debug,  // Request level
        qb::http::LogLevel::Warning // Response level
    );
    configure_router_and_run(logging_mw, create_request(), qb::http::status::HTTP_STATUS_NOT_FOUND);

    ASSERT_EQ(_session->_log_entries.size(), 2);
    EXPECT_EQ(_session->_log_entries[0].first, qb::http::LogLevel::Debug);
    EXPECT_EQ(_session->_log_entries[1].first, qb::http::LogLevel::Warning);
    EXPECT_NE(_session->_log_entries[1].second.find("Response: 404"), std::string::npos);
}

TEST_F(LoggingMiddlewareTest, DifferentHttpMethodsLogging) {
    auto logging_mw = qb::http::logging_middleware<MockLoggingSession>(_test_logger_func);
    configure_router_and_run(logging_mw, create_request(qb::http::method::HTTP_POST, "/log_test"));

    ASSERT_EQ(_session->_log_entries.size(), 2);
    EXPECT_NE(_session->_log_entries[0].second.find("Request: POST /log_test"), std::string::npos);
}

TEST_F(LoggingMiddlewareTest, LoggingWithPathAndQueryParameters) {
    auto logging_mw = qb::http::logging_middleware<MockLoggingSession>(_test_logger_func);
    // Test path parameters by defining a route that would extract them, though logging format might not show them by default.
    // The current format_request only logs method and path.
    // For query parameters, they are part of the URI path.
    _router = std::make_unique<qb::http::Router<MockLoggingSession>>();
    _router->use(logging_mw);
    _router->get("/log_test/item/:id", basic_handler());
    _router->compile();
    
    _session->reset();
    _router->route(_session, create_request(qb::http::method::HTTP_GET, "/log_test/item/123", "param1=val1&param2=val2"));

    ASSERT_EQ(_session->_log_entries.size(), 2);
    // Current format_request only includes path, not full URI with query.
    // To test query params in log, format_request would need to use request.uri().full_path() or similar.
    // For now, we test that path part is logged.
    EXPECT_NE(_session->_log_entries[0].second.find("Request: GET /log_test/item/123"), std::string::npos);
    // If format_request were to include query: 
    // EXPECT_NE(_session->_log_entries[0].second.find("param1=val1&param2=val2"), std::string::npos);
}

TEST_F(LoggingMiddlewareTest, ErrorResponseLogging) {
    auto logging_mw = qb::http::logging_middleware<MockLoggingSession>(_test_logger_func);
    configure_router_and_run(logging_mw, create_request(), qb::http::status::HTTP_STATUS_INTERNAL_SERVER_ERROR);

    ASSERT_EQ(_session->_log_entries.size(), 2);
    EXPECT_NE(_session->_log_entries[1].second.find("Response: 500"), std::string::npos);
}

TEST_F(LoggingMiddlewareTest, ConstructorThrowsOnNullLogFunction) {
    qb::http::LoggingMiddleware<MockLoggingSession>::LogFunction null_logger = nullptr;
    EXPECT_THROW(
        qb::http::LoggingMiddleware<MockLoggingSession> logging_mw(null_logger),
        std::invalid_argument
    );

    // Also test factory function
    EXPECT_THROW(
        qb::http::logging_middleware<MockLoggingSession>(null_logger),
        std::invalid_argument
    );
}

TEST_F(LoggingMiddlewareTest, MiddlewareNameIsCorrect) {
    // Test default name
    auto logging_mw_default_name = qb::http::LoggingMiddleware<MockLoggingSession>(_test_logger_func);
    EXPECT_EQ(logging_mw_default_name.name(), "LoggingMiddleware");

    // Test custom name via constructor
    auto logging_mw_custom_name_ctor = qb::http::LoggingMiddleware<MockLoggingSession>(
        _test_logger_func, 
        qb::http::LogLevel::Info, 
        qb::http::LogLevel::Info, 
        "MyCustomLogger"
    );
    EXPECT_EQ(logging_mw_custom_name_ctor.name(), "MyCustomLogger");

    // Test default name via factory
    auto logging_mw_default_name_factory = qb::http::logging_middleware<MockLoggingSession>(_test_logger_func);
    EXPECT_EQ(logging_mw_default_name_factory->name(), "LoggingMiddleware");

    // Test custom name via factory
    auto logging_mw_custom_name_factory = qb::http::logging_middleware<MockLoggingSession>(
        _test_logger_func, 
        qb::http::LogLevel::Info, 
        qb::http::LogLevel::Info, 
        "MyFactoryLogger"
    );
    EXPECT_EQ(logging_mw_custom_name_factory->name(), "MyFactoryLogger");
}

TEST_F(LoggingMiddlewareTest, QueryParametersExcludedFromRequestLog) {
    auto logging_mw = qb::http::logging_middleware<MockLoggingSession>(_test_logger_func);
    
    _router = std::make_unique<qb::http::Router<MockLoggingSession>>(); // Reset router for this specific test
    _router->use(logging_mw);
    _router->get("/log_test_query", basic_handler()); // Use a unique path for this test
    _router->compile();
    
    _session->reset();
    // Create request with query parameters
    _router->route(_session, create_request(qb::http::method::HTTP_GET, "/log_test_query", "param1=value1&param2=value2"));

    ASSERT_EQ(_session->_log_entries.size(), 2);
    EXPECT_EQ(_session->_log_entries[0].first, qb::http::LogLevel::Info);
    
    const std::string& request_log_message = _session->_log_entries[0].second;
    // Check that the base path is logged
    EXPECT_NE(request_log_message.find("Request: GET /log_test_query"), std::string::npos);
    // Check that query parameters are NOT logged
    EXPECT_EQ(request_log_message.find("param1=value1"), std::string::npos);
    EXPECT_EQ(request_log_message.find("param2=value2"), std::string::npos);
    EXPECT_EQ(request_log_message.find("?"), std::string::npos); // Ensure the query string separator '?' is not present
}

TEST_F(LoggingMiddlewareTest, LogsRequestToRootPath) {
    auto logging_mw = qb::http::logging_middleware<MockLoggingSession>(_test_logger_func);
    
    _router = std::make_unique<qb::http::Router<MockLoggingSession>>();
    _router->use(logging_mw);
    _router->get("/", basic_handler()); // Route for root path
    _router->compile();
    
    _session->reset();
    _router->route(_session, create_request(qb::http::method::HTTP_GET, "/"));

    ASSERT_EQ(_session->_log_entries.size(), 2);
    EXPECT_EQ(_session->_log_entries[0].first, qb::http::LogLevel::Info);
    EXPECT_NE(_session->_log_entries[0].second.find("Request: GET /"), std::string::npos);
    
    EXPECT_EQ(_session->_log_entries[1].first, qb::http::LogLevel::Debug);
    EXPECT_NE(_session->_log_entries[1].second.find("Response: 200"), std::string::npos);
}

TEST_F(LoggingMiddlewareTest, LogsRequestPathWithTrailingSlash) {
    auto logging_mw = qb::http::logging_middleware<MockLoggingSession>(_test_logger_func);

    _router = std::make_unique<qb::http::Router<MockLoggingSession>>();
    _router->use(logging_mw);
    _router->get("/test_trailing_slash/", basic_handler());
    _router->compile();

    _session->reset();
    _router->route(_session, create_request(qb::http::method::HTTP_GET, "/test_trailing_slash/"));

    ASSERT_EQ(_session->_log_entries.size(), 2);
    EXPECT_EQ(_session->_log_entries[0].first, qb::http::LogLevel::Info);
    // The uri().path() method used in format_request_info typically normalizes paths, 
    // so whether the trailing slash is present in the log might depend on qb::io::uri behavior.
    // We'll expect it to be present as per the input for now and adjust if qb::io::uri normalizes it away.
    EXPECT_NE(_session->_log_entries[0].second.find("Request: GET /test_trailing_slash/"), std::string::npos);
}

TEST_F(LoggingMiddlewareTest, LogsVariousStatusCodes) {
    auto logging_mw = qb::http::logging_middleware<MockLoggingSession>(_test_logger_func);
    
    // Test Case 1: 101 Switching Protocols
    _router = std::make_unique<qb::http::Router<MockLoggingSession>>();
    _router->use(logging_mw);
    _router->get("/path101", basic_handler(qb::http::status::HTTP_STATUS_SWITCHING_PROTOCOLS));
    _router->compile();
    _session->reset();
    _router->route(_session, create_request(qb::http::method::HTTP_GET, "/path101"));
    ASSERT_EQ(_session->_log_entries.size(), 2);
    EXPECT_NE(_session->_log_entries[1].second.find("Response: 101"), std::string::npos);

    // Test Case 2: 201 Created
    _router = std::make_unique<qb::http::Router<MockLoggingSession>>();
    _router->use(logging_mw);
    _router->post("/path201", basic_handler(qb::http::status::HTTP_STATUS_CREATED));
    _router->compile();
    _session->reset();
    _router->route(_session, create_request(qb::http::method::HTTP_POST, "/path201"));
    ASSERT_EQ(_session->_log_entries.size(), 2);
    EXPECT_NE(_session->_log_entries[1].second.find("Response: 201"), std::string::npos);

    // Test Case 3: 204 No Content
    _router = std::make_unique<qb::http::Router<MockLoggingSession>>();
    _router->use(logging_mw);
    _router->del("/path204", basic_handler(qb::http::status::HTTP_STATUS_NO_CONTENT));
    _router->compile();
    _session->reset();
    _router->route(_session, create_request(qb::http::method::HTTP_DELETE, "/path204"));
    ASSERT_EQ(_session->_log_entries.size(), 2);
    EXPECT_NE(_session->_log_entries[1].second.find("Response: 204"), std::string::npos);

    // Test Case 4: 302 Found (Redirection)
    _router = std::make_unique<qb::http::Router<MockLoggingSession>>();
    _router->use(logging_mw);
    _router->get("/path302", basic_handler(qb::http::status::HTTP_STATUS_FOUND));
    _router->compile();
    _session->reset();
    _router->route(_session, create_request(qb::http::method::HTTP_GET, "/path302"));
    ASSERT_EQ(_session->_log_entries.size(), 2);
    EXPECT_NE(_session->_log_entries[1].second.find("Response: 302"), std::string::npos);
}

// Note: 
// - RequestBodyLogging and RequestTimingLogging are not features of this basic LoggingMiddleware.
//   Timing would be a separate TimingMiddleware. Body logging would require specific options and logic.

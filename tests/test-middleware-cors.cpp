#include <gtest/gtest.h>
#include "../http.h" 
#include "../middleware/cors.h" // The adapted CorsMiddleware
#include "../routing/middleware.h" // For MiddlewareTask if needed

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <sstream>

// --- Mock Session for CorsMiddleware Tests ---
struct MockCorsSession {
    qb::http::Response _response;
    std::string _session_id_str = "cors_test_session";
    bool _final_handler_called = false;

    qb::http::Response& get_response_ref() { return _response; }

    MockCorsSession& operator<<(const qb::http::Response& resp) {
        _response = resp;
        return *this;
    }

    void reset() {
        _response = qb::http::Response();
        _final_handler_called = false;
    }
};

// --- Test Fixture for CorsMiddleware --- 
class CorsMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockCorsSession> _session;
    std::unique_ptr<qb::http::Router<MockCorsSession>> _router;

    void SetUp() override {
        _session = std::make_shared<MockCorsSession>();
        _router = std::make_unique<qb::http::Router<MockCorsSession>>();
    }

    qb::http::Request create_request(qb::http::method method = qb::http::method::GET,
                                     const std::string& target_path = "/cors_test",
                                     const std::string& origin_header = "") {
        qb::http::Request req;
        req.method() = method;
        try {
            req.uri() = qb::io::uri(target_path);
        } catch (const std::exception& e) {
            ADD_FAILURE() << "URI parse failure: " << target_path << " (" << e.what() << ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        if (!origin_header.empty()) {
            req.set_header("Origin", origin_header);
        }
        return req;
    }

    qb::http::RouteHandlerFn<MockCorsSession> basic_success_handler() {
        return [this](std::shared_ptr<qb::http::Context<MockCorsSession>> ctx) {
            if (_session) _session->_final_handler_called = true;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "CORS Test Handler Executed";
            ctx->complete();
        };
    }

    void configure_router_and_run(std::shared_ptr<qb::http::CorsMiddleware<MockCorsSession>> cors_mw, 
                                  qb::http::Request request) {
        // Re-initialize router to ensure a clean state for each test run
        _router = std::make_unique<qb::http::Router<MockCorsSession>>(); 
        _router->use(cors_mw);
        _router->get("/cors_test", basic_success_handler());
        _router->options("/cors_test", basic_success_handler()); // For OPTIONS preflight
        _router->compile();
        
        _session->reset();
        _router->route(_session, std::move(request));
    }
};

// --- Test Cases --- 

TEST_F(CorsMiddlewareTest, AllowSpecificOrigin) {
    qb::http::CorsOptions options;
    options.origins({"http://example.com"});
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(options);
    
    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "http://example.com"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://example.com");
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, OriginNotAllowed) {
    qb::http::CorsOptions options;
    options.origins({"http://example.com"});
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(options);

    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "http://other.com"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK); // Request still goes through
    EXPECT_TRUE(_session->_response.header("Access-Control-Allow-Origin").empty()); // But no CORS headers
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, AllowAnyOriginWildcard) {
    qb::http::CorsOptions options;
    options.origins({"*"}); // Allow any origin
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(options);

    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "http://random.org"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "*");
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, PreflightRequest) {
    qb::http::CorsOptions options;
    options.origins({"http://localhost:3000"})
           .methods({"GET", "POST", "OPTIONS"})
           .headers({"Content-Type", "Authorization"})
           .max_age(3600);
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(options);

    auto req = create_request(qb::http::method::OPTIONS, "/cors_test", "http://localhost:3000");
    req.set_header("Access-Control-Request-Method", "POST");
    req.set_header("Access-Control-Request-Headers", "Content-Type, Authorization");
    
    configure_router_and_run(cors_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::NO_CONTENT);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://localhost:3000");
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Methods")), "GET, POST, OPTIONS");
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Headers")), "Content-Type, Authorization");
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Max-Age")), "3600");
    EXPECT_FALSE(_session->_final_handler_called); // Preflight should be handled by CORS MW
}

TEST_F(CorsMiddlewareTest, ActualRequestWithCorsHeaders) {
    qb::http::CorsOptions options;
    options.origins({"http://example.com"})
           .expose_headers({"X-My-Custom-Header", "Content-Length"});
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(options);

    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "http://example.com"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://example.com");
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Expose-Headers")), "X-My-Custom-Header, Content-Length");
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, CredentialsAllowed) {
    qb::http::CorsOptions options;
    options.origins({"http://creds.example.com"})
           .credentials(qb::http::CorsOptions::AllowCredentials::Yes);
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(options);

    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "http://creds.example.com"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://creds.example.com");
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Credentials")), "true");
}

TEST_F(CorsMiddlewareTest, NoOriginHeader) {
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(qb::http::CorsOptions().origins({"http://example.com"}));
    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "")); // No Origin header

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.header("Access-Control-Allow-Origin").empty());
    EXPECT_TRUE(_session->_final_handler_called); // Should proceed as normal without CORS
}

TEST_F(CorsMiddlewareTest, PreflightRequestExposedHeaders) {
    qb::http::CorsOptions options;
    options.origins({"http://example.com"})
           .methods({"GET", "POST", "OPTIONS"})
           .headers({"X-My-Custom-Header", "Content-Length"})
           .max_age(3600)
           .expose_headers({"X-My-Custom-Header", "Content-Length"});
    
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(options);

    auto req = create_request(qb::http::method::OPTIONS, "/cors_test", "http://example.com");
    req.set_header("Access-Control-Request-Method", "POST");
    req.set_header("Access-Control-Request-Headers", "X-My-Custom-Header, Content-Length");

    configure_router_and_run(cors_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::NO_CONTENT);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://example.com");
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Methods")), "GET, POST, OPTIONS");
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Headers")), "X-My-Custom-Header, Content-Length");
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Max-Age")), "3600");
    EXPECT_FALSE(_session->_final_handler_called); // Preflight should be handled by CORS MW
}

TEST_F(CorsMiddlewareTest, FactoryFunctions) {
    auto dev_mw = qb::http::CorsMiddleware<MockCorsSession>::dev();
    EXPECT_EQ(dev_mw->name(), "DevCorsMiddleware");
    EXPECT_TRUE(dev_mw->get_cors_options().is_origin_allowed("http://any.origin.com"));

    auto secure_mw = qb::http::CorsMiddleware<MockCorsSession>::secure({"https://secure.com"});
    EXPECT_EQ(secure_mw->name(), "SecureCorsMiddleware");
    EXPECT_TRUE(secure_mw->get_cors_options().is_origin_allowed("https://secure.com"));
    EXPECT_FALSE(secure_mw->get_cors_options().is_origin_allowed("http://notsecure.com"));
}

TEST_F(CorsMiddlewareTest, RegexOriginMatching) {
    qb::http::CorsOptions options;
    // Allow any subdomain of example.com and example.com itself for http
    options.origin_patterns({"http://.*\\.example\\.com", "http://example\\.com"}); 
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(options);

    // Test case 1: Origin matches regex (subdomain)
    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "http://sub.example.com"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://sub.example.com");
    EXPECT_TRUE(_session->_final_handler_called);

    _session->reset(); // Reset session for next sub-test

    // Test case 2: Origin matches regex (main domain)
    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "http://example.com"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://example.com");
    EXPECT_TRUE(_session->_final_handler_called);

    _session->reset();

    // Test case 3: Origin does not match regex
    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "http://another.domain.com"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.header("Access-Control-Allow-Origin").empty());
    EXPECT_TRUE(_session->_final_handler_called);

    _session->reset();

    // Test case 4: Origin matches regex (different subdomain)
    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "http://www.example.com"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://www.example.com");
    EXPECT_TRUE(_session->_final_handler_called);

    _session->reset();

    // Test case 5: Scheme mismatch (https instead of http)
    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "https://sub.example.com"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.header("Access-Control-Allow-Origin").empty());
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, FunctionOriginMatching) {
    qb::http::CorsOptions options;
    auto custom_origin_matcher = [](const std::string& origin) -> bool {
        if (origin == "http://allowed.by.function.com") {
            return true;
        }
        if (origin == "https://another.functional.match") {
            return true;
        }
        return false;
    };
    options.origin_matcher(custom_origin_matcher);
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(options);

    // Test case 1: Origin allowed by function
    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "http://allowed.by.function.com"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://allowed.by.function.com");
    EXPECT_TRUE(_session->_final_handler_called);

    _session->reset();

    // Test case 2: Another origin allowed by function
    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "https://another.functional.match"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "https://another.functional.match");
    EXPECT_TRUE(_session->_final_handler_called);

    _session->reset();

    // Test case 3: Origin not allowed by function
    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "http://denied.by.function.com"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.header("Access-Control-Allow-Origin").empty());
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, PreflightAllowHeadersDetailed) {
    qb::http::CorsOptions options;
    options.origins({"http://example.com"})
           .methods({"GET", "POST", "OPTIONS"})
           .headers({"Content-Type", "Authorization", "X-Custom-Header", "X-Another-Header"})
           .max_age(3600);
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(options);

    // Scenario 1: Request asks for a subset of allowed headers
    auto req1 = create_request(qb::http::method::OPTIONS, "/cors_test", "http://example.com");
    req1.set_header("Access-Control-Request-Method", "POST");
    req1.set_header("Access-Control-Request-Headers", "Content-Type, X-Custom-Header"); // Asking for a subset
    
    configure_router_and_run(cors_mw, std::move(req1));

    EXPECT_EQ(_session->_response.status(), qb::http::status::NO_CONTENT);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://example.com");
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Methods")), "GET, POST, OPTIONS");
    // Should echo back the *requested and allowed* headers
    // The order might not be guaranteed, so we should check for individual headers or parse and compare sets.
    // For simplicity, checking for a comma-separated string is okay if the middleware guarantees order or if we sort.
    // Let's assume the middleware might not guarantee order of echoed headers for now, 
    // so we'll check for the presence of each requested header and ensure no non-requested ones are there.
    std::string allowed_headers_str = std::string(_session->_response.header("Access-Control-Allow-Headers"));
    EXPECT_TRUE(allowed_headers_str.find("Content-Type") != std::string::npos);
    EXPECT_TRUE(allowed_headers_str.find("X-Custom-Header") != std::string::npos);
    EXPECT_FALSE(allowed_headers_str.find("Authorization") != std::string::npos); // Was not requested
    EXPECT_FALSE(allowed_headers_str.find("X-Another-Header") != std::string::npos); // Was not requested
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Max-Age")), "3600");
    EXPECT_FALSE(_session->_final_handler_called);

    _session->reset();

    // Scenario 2: Request does not send Access-Control-Request-Headers
    // The Access-Control-Allow-Headers in response should list all configured allowed headers.
    auto req2 = create_request(qb::http::method::OPTIONS, "/cors_test", "http://example.com");
    req2.set_header("Access-Control-Request-Method", "GET");
    // No Access-Control-Request-Headers from client

    configure_router_and_run(cors_mw, std::move(req2));
    EXPECT_EQ(_session->_response.status(), qb::http::status::NO_CONTENT);
    allowed_headers_str = std::string(_session->_response.header("Access-Control-Allow-Headers"));
    // Check if all configured headers are present
    EXPECT_TRUE(allowed_headers_str.find("Content-Type") != std::string::npos);
    EXPECT_TRUE(allowed_headers_str.find("Authorization") != std::string::npos);
    EXPECT_TRUE(allowed_headers_str.find("X-Custom-Header") != std::string::npos);
    EXPECT_TRUE(allowed_headers_str.find("X-Another-Header") != std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);

    _session->reset();

    // Scenario 3: CorsOptions.headers() is empty, but request sends Access-Control-Request-Headers
    qb::http::CorsOptions options_no_allowed_headers;
    options_no_allowed_headers.origins({"http://example.com"})
                              .methods({"GET", "POST", "OPTIONS"})
                              .max_age(3600);
    // .headers({}) is default empty
    auto cors_mw_no_headers = qb::http::cors_middleware<MockCorsSession>(options_no_allowed_headers);

    auto req3 = create_request(qb::http::method::OPTIONS, "/cors_test", "http://example.com");
    req3.set_header("Access-Control-Request-Method", "POST");
    req3.set_header("Access-Control-Request-Headers", "X-Should-Not-Be-Allowed");

    configure_router_and_run(cors_mw_no_headers, std::move(req3));
    EXPECT_EQ(_session->_response.status(), qb::http::status::NO_CONTENT);
    // Access-Control-Allow-Headers should be empty or not present if no headers are explicitly allowed by server
    // and client requests some. Current behavior is to send empty string if no match.
    std::string actual_allow_headers = std::string(_session->_response.header("Access-Control-Allow-Headers"));
    EXPECT_EQ(actual_allow_headers, "") << "Access-Control-Allow-Headers was: [" << actual_allow_headers << "]";
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, WildcardOriginWithCredentials) {
    qb::http::CorsOptions options;
    options.origins({"*"}) // Wildcard origin
           .credentials(qb::http::CorsOptions::AllowCredentials::Yes); // Credentials allowed
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(options);

    // Request from a specific origin
    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "http://specific.example.com"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    // With credentials, '*' should be replaced by the specific requesting origin
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://specific.example.com");
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Credentials")), "true");
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, PreflightServerNoHeadersClientNoHeaders) {
    qb::http::CorsOptions options;
    options.origins({"http://example.com"})
           .methods({"GET", "POST"});
    // No .headers() call, so server has no configured allowed headers by default
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(options);

    auto req = create_request(qb::http::method::OPTIONS, "/cors_test", "http://example.com");
    req.set_header("Access-Control-Request-Method", "POST");
    // Client also sends no Access-Control-Request-Headers

    configure_router_and_run(cors_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::NO_CONTENT);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://example.com");
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Methods")), "GET, POST");
    // Access-Control-Allow-Headers should be empty or not present
    std::string actual_allow_headers = std::string(_session->_response.header("Access-Control-Allow-Headers"));
    EXPECT_TRUE(actual_allow_headers.empty()) << "Access-Control-Allow-Headers was: [" << actual_allow_headers << "]";
    
    std::string vary_header = std::string(_session->_response.header("Vary"));
    EXPECT_NE(vary_header.find("Origin"), std::string::npos);
    // Vary header should not contain Access-Control-Request-Headers if client didn't send it
    // and server did not add Allow-Headers based on it.
    // The current middleware adds Vary: Access-Control-Request-Headers only if it processes client requested headers.
    // If client sends no requested headers, and server has none, then Allow-Headers is empty and Vary for it isn't added.
    // If client sends no requested headers, and server has some, server lists all its headers, and Vary for A-C-R-H is not added.
    // This check is valid under the current logic.
    EXPECT_EQ(vary_header.find("Access-Control-Request-Headers"), std::string::npos);

    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, PreflightCaseInsensitiveRequestHeaders) {
    qb::http::CorsOptions options;
    options.origins({"http://example.com"})
           .methods({"PUT"})
           .headers({"CoNtEnT-TyPe", "X-API-KEY", "Authorization"}); // Server configured with mixed case
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(options);

    auto req = create_request(qb::http::method::OPTIONS, "/cors_test", "http://example.com");
    req.set_header("Access-Control-Request-Method", "PUT");
    // Client requests with different casing and a non-allowed header
    req.set_header("Access-Control-Request-Headers", "content-type, x-api-key, X-Non-Allowed-Header"); 
    
    configure_router_and_run(cors_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::NO_CONTENT);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://example.com");
    std::string allowed_headers_str = std::string(_session->_response.header("Access-Control-Allow-Headers"));
    
    // Check that the allowed headers are present, potentially echoed in the client's requested case
    EXPECT_TRUE(allowed_headers_str.find("content-type") != std::string::npos || allowed_headers_str.find("CoNtEnT-TyPe") != std::string::npos);
    EXPECT_TRUE(allowed_headers_str.find("x-api-key") != std::string::npos || allowed_headers_str.find("X-API-KEY") != std::string::npos);
    EXPECT_FALSE(allowed_headers_str.find("Authorization") != std::string::npos); // Was not requested by client
    EXPECT_FALSE(allowed_headers_str.find("X-Non-Allowed-Header") != std::string::npos); // Was not allowed by server
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(CorsMiddlewareTest, MultipleExactOrigins) {
    qb::http::CorsOptions options;
    options.origins({"http://site1.com", "https://site2.org"});
    auto cors_mw = qb::http::cors_middleware<MockCorsSession>(options);

    // Test case 1: Origin matches first allowed origin
    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "http://site1.com"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://site1.com");
    EXPECT_TRUE(_session->_final_handler_called);
    _session->reset();

    // Test case 2: Origin matches second allowed origin
    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "https://site2.org"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "https://site2.org");
    EXPECT_TRUE(_session->_final_handler_called);
    _session->reset();

    // Test case 3: Origin does not match any allowed origin
    configure_router_and_run(cors_mw, create_request(qb::http::method::GET, "/cors_test", "http://othersite.net"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.header("Access-Control-Allow-Origin").empty());
    EXPECT_TRUE(_session->_final_handler_called);
    _session->reset();

    // Test case 4: Different path, but still matching origin
    _session->reset(); 
    _router = std::make_unique<qb::http::Router<MockCorsSession>>(); 
    _router->use(cors_mw); 
    _router->get("/cors_test", basic_success_handler()); 
    _router->options("/cors_test", basic_success_handler()); 
    _router->get("/another_path", basic_success_handler()); 
    _router->compile();
    
    auto req_tc4 = create_request(qb::http::method::GET, "/another_path", "http://site1.com"); // Corrected typo
    _router->route(_session, std::move(req_tc4));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Access-Control-Allow-Origin")), "http://site1.com");
    EXPECT_TRUE(_session->_final_handler_called);
}

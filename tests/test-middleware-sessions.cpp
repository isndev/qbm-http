#include <gtest/gtest.h>
#include <string>
#include <memory>
#include <map>

#include "../http.h"
#include "../middleware/sessions.h"
#include "../middleware/middleware_interface.h"
#include "../middleware/middleware_chain.h"

using namespace qb::http;

// Mock Session class for testing
class MockSession {
public:
    void operator<<(const Response& resp) {
        last_response = std::move(const_cast<Response&>(resp));
        responses.push_back(last_response);
    }
    
    std::string get_client_ip() const {
        return "192.168.1.100";
    }
    
    std::string id() const {
        return "test-session-id";
    }
    
    bool is_connected() const {
        return true;
    }
    
    Response last_response;
    std::vector<Response> responses;
};

// Mock session store for testing
class MockSessionStore : public SessionStoreInterface {
public:
    bool create(const std::string& session_id, const std::map<std::string, std::string>& data) override {
        sessions[session_id] = data;
        return true;
    }
    
    bool get(const std::string& session_id, std::map<std::string, std::string>& data) override {
        if (sessions.find(session_id) == sessions.end()) {
            return false;
        }
        data = sessions[session_id];
        return true;
    }
    
    bool update(const std::string& session_id, const std::map<std::string, std::string>& data) override {
        if (sessions.find(session_id) == sessions.end()) {
            return false;
        }
        sessions[session_id] = data;
        return true;
    }
    
    bool destroy(const std::string& session_id) override {
        if (sessions.find(session_id) == sessions.end()) {
            return false;
        }
        sessions.erase(session_id);
        return true;
    }
    
    std::map<std::string, std::map<std::string, std::string>> sessions;
};

// Test fixture
class SessionsTest : public ::testing::Test {
protected:
    void SetUp() override {
        session = std::make_shared<MockSession>();
        store = std::make_shared<MockSessionStore>();
        
        // Create a request
        request.method = HTTP_GET;
        request._uri = "/api/test";
    }
    
    std::shared_ptr<MockSession> session;
    std::shared_ptr<MockSessionStore> store;
    Request request;
    
    // Helper to create a context
    Context<MockSession> create_context() {
        return Context<MockSession>(session, request);
    }
};

// Test session creation
TEST_F(SessionsTest, SessionCreation) {
    // Create session options
    SessionOptions options;
    options.store = store;
    options.cookie_name = "test_session";
    
    // Create middleware
    auto middleware = std::make_shared<SessionMiddleware<MockSession>>(options);
    
    // Process a request without session cookie
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Should continue to next middleware
    EXPECT_TRUE(result.should_continue());
    
    // Should create a new session
    EXPECT_TRUE(ctx.has("session"));
    auto& session_data = ctx.get<std::map<std::string, std::string>>("session");
    EXPECT_TRUE(session_data.empty());
    
    // Should set a session cookie
    EXPECT_TRUE(ctx.response.has_header("Set-Cookie"));
    std::string cookie = ctx.response.get_header("Set-Cookie");
    EXPECT_TRUE(cookie.find("test_session=") != std::string::npos);
    
    // Extract session ID from cookie
    std::string session_id;
    size_t pos = cookie.find("test_session=");
    if (pos != std::string::npos) {
        size_t start = pos + 13; // Length of "test_session="
        size_t end = cookie.find(";", start);
        if (end != std::string::npos) {
            session_id = cookie.substr(start, end - start);
        } else {
            session_id = cookie.substr(start);
        }
    }
    
    // Verify session was stored in backend
    EXPECT_FALSE(session_id.empty());
    EXPECT_TRUE(store->sessions.find(session_id) != store->sessions.end());
}

// Test session retrieval
TEST_F(SessionsTest, SessionRetrieval) {
    // Create a session in the store
    std::string session_id = "test-session-123";
    std::map<std::string, std::string> data = {
        {"user_id", "123"},
        {"username", "testuser"}
    };
    store->sessions[session_id] = data;
    
    // Add session cookie to request
    request.add_header("Cookie", "test_session=" + session_id);
    
    // Create session options
    SessionOptions options;
    options.store = store;
    options.cookie_name = "test_session";
    
    // Create middleware
    auto middleware = std::make_shared<SessionMiddleware<MockSession>>(options);
    
    // Process the request
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Should continue to next middleware
    EXPECT_TRUE(result.should_continue());
    
    // Should retrieve the session
    EXPECT_TRUE(ctx.has("session"));
    auto& session_data = ctx.get<std::map<std::string, std::string>>("session");
    EXPECT_EQ(2, session_data.size());
    EXPECT_EQ("123", session_data["user_id"]);
    EXPECT_EQ("testuser", session_data["username"]);
    
    // Should not set a new cookie since we already have one
    EXPECT_FALSE(ctx.response.has_header("Set-Cookie"));
}

// Test session modification
TEST_F(SessionsTest, SessionModification) {
    // Create a session in the store
    std::string session_id = "test-session-123";
    std::map<std::string, std::string> data = {
        {"user_id", "123"},
        {"username", "testuser"}
    };
    store->sessions[session_id] = data;
    
    // Add session cookie to request
    request.add_header("Cookie", "test_session=" + session_id);
    
    // Create session options
    SessionOptions options;
    options.store = store;
    options.cookie_name = "test_session";
    
    // Create middleware
    auto middleware = std::make_shared<SessionMiddleware<MockSession>>(options);
    
    // Process the request
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Modify session data
    auto& session_data = ctx.get<std::map<std::string, std::string>>("session");
    session_data["new_key"] = "new_value";
    session_data["username"] = "updated_user";
    
    // Finalize the request (this should save the session)
    middleware->after_request(ctx);
    
    // Verify session was updated in store
    EXPECT_EQ(3, store->sessions[session_id].size());
    EXPECT_EQ("123", store->sessions[session_id]["user_id"]);
    EXPECT_EQ("updated_user", store->sessions[session_id]["username"]);
    EXPECT_EQ("new_value", store->sessions[session_id]["new_key"]);
}

// Test session destruction
TEST_F(SessionsTest, SessionDestruction) {
    // Create a session in the store
    std::string session_id = "test-session-123";
    std::map<std::string, std::string> data = {
        {"user_id", "123"},
        {"username", "testuser"}
    };
    store->sessions[session_id] = data;
    
    // Add session cookie to request
    request.add_header("Cookie", "test_session=" + session_id);
    
    // Create session options
    SessionOptions options;
    options.store = store;
    options.cookie_name = "test_session";
    
    // Create middleware
    auto middleware = std::make_shared<SessionMiddleware<MockSession>>(options);
    
    // Process the request
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Destroy the session
    ctx.get<std::map<std::string, std::string>>("session").clear();
    ctx.set("session_destroy", true);
    
    // Finalize the request
    middleware->after_request(ctx);
    
    // Verify session was removed from store
    EXPECT_TRUE(store->sessions.find(session_id) == store->sessions.end());
    
    // Verify cookie was invalidated
    EXPECT_TRUE(ctx.response.has_header("Set-Cookie"));
    std::string cookie = ctx.response.get_header("Set-Cookie");
    EXPECT_TRUE(cookie.find("test_session=;") != std::string::npos);
    EXPECT_TRUE(cookie.find("Max-Age=0") != std::string::npos);
}

// Test session with expiration
TEST_F(SessionsTest, SessionExpiration) {
    // Create session options with expiration
    SessionOptions options;
    options.store = store;
    options.cookie_name = "test_session";
    options.max_age = 3600; // 1 hour
    
    // Create middleware
    auto middleware = std::make_shared<SessionMiddleware<MockSession>>(options);
    
    // Process a request without session cookie
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Should set a session cookie with expiration
    EXPECT_TRUE(ctx.response.has_header("Set-Cookie"));
    std::string cookie = ctx.response.get_header("Set-Cookie");
    EXPECT_TRUE(cookie.find("Max-Age=3600") != std::string::npos);
}

// Test secure session cookie
TEST_F(SessionsTest, SecureSessionCookie) {
    // Create session options with secure flag
    SessionOptions options;
    options.store = store;
    options.cookie_name = "test_session";
    options.secure = true;
    
    // Create middleware
    auto middleware = std::make_shared<SessionMiddleware<MockSession>>(options);
    
    // Process a request without session cookie
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Should set a secure session cookie
    EXPECT_TRUE(ctx.response.has_header("Set-Cookie"));
    std::string cookie = ctx.response.get_header("Set-Cookie");
    EXPECT_TRUE(cookie.find("Secure") != std::string::npos);
}

// Test HTTP-only session cookie
TEST_F(SessionsTest, HttpOnlySessionCookie) {
    // Create session options with HTTP-only flag
    SessionOptions options;
    options.store = store;
    options.cookie_name = "test_session";
    options.http_only = true;
    
    // Create middleware
    auto middleware = std::make_shared<SessionMiddleware<MockSession>>(options);
    
    // Process a request without session cookie
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Should set an HTTP-only session cookie
    EXPECT_TRUE(ctx.response.has_header("Set-Cookie"));
    std::string cookie = ctx.response.get_header("Set-Cookie");
    EXPECT_TRUE(cookie.find("HttpOnly") != std::string::npos);
}

// Test with SameSite attribute
TEST_F(SessionsTest, SameSiteSessionCookie) {
    // Create session options with SameSite=Strict
    SessionOptions options;
    options.store = store;
    options.cookie_name = "test_session";
    options.same_site = "Strict";
    
    // Create middleware
    auto middleware = std::make_shared<SessionMiddleware<MockSession>>(options);
    
    // Process a request without session cookie
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Should set a session cookie with SameSite
    EXPECT_TRUE(ctx.response.has_header("Set-Cookie"));
    std::string cookie = ctx.response.get_header("Set-Cookie");
    EXPECT_TRUE(cookie.find("SameSite=Strict") != std::string::npos);
}

// Test with domain attribute
TEST_F(SessionsTest, DomainSessionCookie) {
    // Create session options with domain
    SessionOptions options;
    options.store = store;
    options.cookie_name = "test_session";
    options.domain = "example.com";
    
    // Create middleware
    auto middleware = std::make_shared<SessionMiddleware<MockSession>>(options);
    
    // Process a request without session cookie
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Should set a session cookie with domain
    EXPECT_TRUE(ctx.response.has_header("Set-Cookie"));
    std::string cookie = ctx.response.get_header("Set-Cookie");
    EXPECT_TRUE(cookie.find("Domain=example.com") != std::string::npos);
}

// Test with path attribute
TEST_F(SessionsTest, PathSessionCookie) {
    // Create session options with path
    SessionOptions options;
    options.store = store;
    options.cookie_name = "test_session";
    options.path = "/app";
    
    // Create middleware
    auto middleware = std::make_shared<SessionMiddleware<MockSession>>(options);
    
    // Process a request without session cookie
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Should set a session cookie with path
    EXPECT_TRUE(ctx.response.has_header("Set-Cookie"));
    std::string cookie = ctx.response.get_header("Set-Cookie");
    EXPECT_TRUE(cookie.find("Path=/app") != std::string::npos);
}

// Test factory methods
TEST_F(SessionsTest, FactoryMethods) {
    // Test with default options
    {
        auto middleware = session_middleware<MockSession>(store);
        
        // Process a request without session cookie
        auto ctx = create_context();
        auto result = middleware->process(ctx);
        
        // Should create a session
        EXPECT_TRUE(ctx.has("session"));
        EXPECT_TRUE(ctx.response.has_header("Set-Cookie"));
        std::string cookie = ctx.response.get_header("Set-Cookie");
        EXPECT_TRUE(cookie.find("qb_session=") != std::string::npos);
    }
    
    // Test with custom options
    {
        SessionOptions options;
        options.store = store;
        options.cookie_name = "custom_session";
        options.http_only = true;
        options.secure = true;
        
        auto middleware = session_middleware<MockSession>(options);
        
        // Process a request without session cookie
        auto ctx = create_context();
        auto result = middleware->process(ctx);
        
        // Should create a session with custom options
        EXPECT_TRUE(ctx.has("session"));
        EXPECT_TRUE(ctx.response.has_header("Set-Cookie"));
        std::string cookie = ctx.response.get_header("Set-Cookie");
        EXPECT_TRUE(cookie.find("custom_session=") != std::string::npos);
        EXPECT_TRUE(cookie.find("HttpOnly") != std::string::npos);
        EXPECT_TRUE(cookie.find("Secure") != std::string::npos);
    }
}

// Test middleware chain integration
TEST_F(SessionsTest, MiddlewareChainIntegration) {
    // Create a middleware that uses session data
    class SessionUserMiddleware : public MiddlewareInterface<MockSession> {
    public:
        MiddlewareResult process(Context<MockSession>& ctx) override {
            if (ctx.has("session")) {
                auto& session_data = ctx.get<std::map<std::string, std::string>>("session");
                
                // Set a user ID in the session
                session_data["user_id"] = "user123";
                
                // Set the user in the context
                ctx.set("user_id", "user123");
            }
            
            return MiddlewareResult::continue_();
        }
    };
    
    // Create session middleware
    SessionOptions options;
    options.store = store;
    options.cookie_name = "test_session";
    
    auto session_mw = std::make_shared<SessionMiddleware<MockSession>>(options);
    auto user_mw = std::make_shared<SessionUserMiddleware>();
    
    // Create middleware chain
    MiddlewareChain<MockSession> chain;
    chain.add(session_mw);
    chain.add(user_mw);
    
    // Process the chain
    auto ctx = create_context();
    chain.process(ctx);
    
    // Should have a session
    EXPECT_TRUE(ctx.has("session"));
    
    // Should have a user ID in both context and session
    EXPECT_TRUE(ctx.has("user_id"));
    EXPECT_EQ("user123", ctx.get<std::string>("user_id"));
    
    auto& session_data = ctx.get<std::map<std::string, std::string>>("session");
    EXPECT_EQ("user123", session_data["user_id"]);
    
    // Extract session ID from cookie
    EXPECT_TRUE(ctx.response.has_header("Set-Cookie"));
    std::string cookie = ctx.response.get_header("Set-Cookie");
    std::string session_id;
    size_t pos = cookie.find("test_session=");
    if (pos != std::string::npos) {
        size_t start = pos + 13; // Length of "test_session="
        size_t end = cookie.find(";", start);
        if (end != std::string::npos) {
            session_id = cookie.substr(start, end - start);
        } else {
            session_id = cookie.substr(start);
        }
    }
    
    // Simulate end of request
    chain.finalize(ctx);
    
    // Verify session was stored
    EXPECT_FALSE(session_id.empty());
    EXPECT_TRUE(store->sessions.find(session_id) != store->sessions.end());
    EXPECT_EQ("user123", store->sessions[session_id]["user_id"]);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
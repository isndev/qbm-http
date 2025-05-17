#include <gtest/gtest.h>
#include "../http.h" 
#include "../middleware/timing.h" // The adapted TimingMiddleware
#include "../routing/middleware.h" // For MiddlewareTask if needed
#include <optional> // Added for std::optional

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <sstream>
#include <chrono>
#include <thread> // For std::this_thread::sleep_for

// --- Mock Session for TimingMiddleware Tests ---
struct MockTimingSession {
    qb::http::Response _response;
    std::string _session_id_str = "timing_test_session";
    std::optional<std::chrono::milliseconds> _last_duration_logged;
    bool _final_handler_called = false;

    qb::http::Response& get_response_ref() { return _response; }

    MockTimingSession& operator<<(const qb::http::Response& resp) {
        _response = resp;
        return *this;
    }

    void reset() {
        _response = qb::http::Response();
        _last_duration_logged.reset();
        _final_handler_called = false;
    }
};

// --- Test Fixture for TimingMiddleware --- 
class TimingMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockTimingSession> _session;
    std::unique_ptr<qb::http::Router<MockTimingSession>> _router;
    // TaskExecutor generally not needed for these tests as the core logic of TimingMiddleware
    // and its hook are synchronous once triggered by the router's lifecycle.

    qb::http::TimingMiddleware<MockTimingSession>::TimingCallback _test_timing_callback;

    void SetUp() override {
        _session = std::make_shared<MockTimingSession>();
        _router = std::make_unique<qb::http::Router<MockTimingSession>>();
        _test_timing_callback = [this](const std::chrono::milliseconds& duration) {
            if (_session) {
                _session->_last_duration_logged = duration;
            }
        };
    }

    qb::http::Request create_request(const std::string& target_path = "/timed_route") {
        qb::http::Request req;
        req.method = qb::http::method::HTTP_GET;
        try {
            req.uri() = qb::io::uri(target_path);
        } catch (const std::exception& e) {
            ADD_FAILURE() << "URI parse failure: " << target_path << " (" << e.what() << ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        return req;
    }

    qb::http::RouteHandlerFn<MockTimingSession> simple_handler(std::chrono::milliseconds delay = std::chrono::milliseconds(0)) {
        return [this, delay](std::shared_ptr<qb::http::Context<MockTimingSession>> ctx) {
            if (delay > std::chrono::milliseconds(0)) {
                std::this_thread::sleep_for(delay);
            }
            if (_session) _session->_final_handler_called = true;
            ctx->response().status_code = qb::http::status::HTTP_STATUS_OK;
            ctx->response().body() = "Handler Executed";
            ctx->complete();
        };
    }

    void configure_router_and_run(std::shared_ptr<qb::http::TimingMiddleware<MockTimingSession>> timing_mw, 
                                  qb::http::Request request,
                                  std::chrono::milliseconds handler_delay = std::chrono::milliseconds(0)) {
        _router->use(timing_mw);
        _router->get("/timed_route", simple_handler(handler_delay));
        _router->compile();
        
        _session->reset();
        _router->route(_session, std::move(request));
        // The lifecycle hook for timing will be executed by the router as part of route processing.
    }
};

// --- Test Cases --- 

TEST_F(TimingMiddlewareTest, BasicTiming) {
    auto timing_mw = qb::http::timing_middleware<MockTimingSession>(_test_timing_callback, "BasicTimer");
    configure_router_and_run(timing_mw, create_request());

    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_last_duration_logged.has_value());
    // Check if duration is non-negative. Exact duration is hard to assert reliably.
    EXPECT_GE(_session->_last_duration_logged->count(), 0);
    // Further checks could be for a reasonable upper bound if the handler was instant.
}

TEST_F(TimingMiddlewareTest, TimingWithHandlerDelay) {
    auto timing_mw = qb::http::timing_middleware<MockTimingSession>(_test_timing_callback, "DelayedTimer");
    std::chrono::milliseconds expected_delay(50); // 50ms delay
    configure_router_and_run(timing_mw, create_request(), expected_delay);

    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_last_duration_logged.has_value());
    // Check if the logged duration is at least the delay, allowing for some overhead.
    EXPECT_GE(_session->_last_duration_logged->count(), expected_delay.count());
    // Add a reasonable upper bound, e.g., delay + 50ms overhead for test environment
    EXPECT_LT(_session->_last_duration_logged->count(), (expected_delay + std::chrono::milliseconds(50)).count()); 
}

TEST_F(TimingMiddlewareTest, CustomNaming) {
    auto timing_mw_custom_name = qb::http::timing_middleware<MockTimingSession>(_test_timing_callback, "MyCustomTimerName");
    EXPECT_EQ(timing_mw_custom_name->name(), "MyCustomTimerName");
    
    // Run a quick request to ensure it works with custom name (duration check is secondary here)
    configure_router_and_run(timing_mw_custom_name, create_request());
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_TRUE(_session->_last_duration_logged.has_value());
}

TEST_F(TimingMiddlewareTest, CallbackIsActuallyCalled) {
    bool callback_was_invoked = false;
    qb::http::TimingMiddleware<MockTimingSession>::TimingCallback custom_cb = 
        [&callback_was_invoked](const std::chrono::milliseconds& /*duration*/) {
        callback_was_invoked = true;
    };
    auto timing_mw = qb::http::timing_middleware<MockTimingSession>(custom_cb);
    configure_router_and_run(timing_mw, create_request());

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_TRUE(callback_was_invoked);
}

TEST_F(TimingMiddlewareTest, TimingCallbackReceivesCorrectDuration) {
    std::optional<std::chrono::milliseconds> secondary_callback_duration;
    bool secondary_callback_invoked = false;

    qb::http::TimingMiddleware<MockTimingSession>::TimingCallback secondary_cb =
        [&](const std::chrono::milliseconds& duration) {
        secondary_callback_duration = duration;
        secondary_callback_invoked = true;
    };

    // We use two different timing middlewares to ensure their context keys don't clash
    // and to simulate a more complex scenario. One uses the fixture's callback, one uses secondary_cb.
    auto timing_mw1 = qb::http::timing_middleware<MockTimingSession>(_test_timing_callback, "Timer1");
    auto timing_mw2 = qb::http::timing_middleware<MockTimingSession>(secondary_cb, "Timer2");

    _router->use(timing_mw1); // This will log to _session->_last_duration_logged
    _router->use(timing_mw2); // This will log to secondary_callback_duration
    _router->get("/timed_route", simple_handler(std::chrono::milliseconds(10)));
    _router->compile();
        
    _session->reset();
    _router->route(_session, create_request());

    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_last_duration_logged.has_value());
    ASSERT_TRUE(secondary_callback_invoked);
    ASSERT_TRUE(secondary_callback_duration.has_value());

    // Check that the durations are very close. Allow a small difference (e.g., 5ms) for overhead.
    EXPECT_GE(_session->_last_duration_logged->count(), 10);
    EXPECT_GE(secondary_callback_duration->count(), 10);
    EXPECT_NEAR(_session->_last_duration_logged->count(), secondary_callback_duration->count(), 5);
}

TEST_F(TimingMiddlewareTest, TimingMultipleRequestsSequentially) {
    auto timing_mw = qb::http::timing_middleware<MockTimingSession>(_test_timing_callback, "SequentialTimer");
    
    // Configure router once with the middleware
    _router->use(timing_mw);
    _router->get("/timed_route", simple_handler(std::chrono::milliseconds(10))); // Handler with 10ms delay
    _router->get("/timed_route_2", simple_handler(std::chrono::milliseconds(20))); // Handler with 20ms delay
    _router->compile();

    // Request 1
    _session->reset();
    _router->route(_session, create_request("/timed_route"));
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_last_duration_logged.has_value());
    EXPECT_GE(_session->_last_duration_logged->count(), 10);
    EXPECT_LT(_session->_last_duration_logged->count(), 60); // 10ms + 50ms buffer
    std::chrono::milliseconds duration1 = *_session->_last_duration_logged;

    // Request 2 - should be independent
    _session->reset();
    _router->route(_session, create_request("/timed_route_2"));
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_last_duration_logged.has_value());
    EXPECT_GE(_session->_last_duration_logged->count(), 20);
    EXPECT_LT(_session->_last_duration_logged->count(), 70); // 20ms + 50ms buffer
    std::chrono::milliseconds duration2 = *_session->_last_duration_logged;

    // Ensure durations are somewhat distinct as per handler delays
    EXPECT_NE(duration1.count(), duration2.count()); 
    // A more robust check might be that duration2 is roughly duration1 + 10ms, but that's too fragile.
    // Simply checking they are roughly what we expect for each handler is sufficient.
}

TEST_F(TimingMiddlewareTest, TimingMiddlewareAddedMultipleTimesSameName) {
    int callback_invocation_count = 0;
    std::vector<std::chrono::milliseconds> durations_logged;
    qb::http::TimingMiddleware<MockTimingSession>::TimingCallback multi_cb =
        [&](const std::chrono::milliseconds& duration) {
        callback_invocation_count++;
        durations_logged.push_back(duration);
    };

    // Add two instances with the SAME name and callback
    auto timing_mw1 = qb::http::timing_middleware<MockTimingSession>(multi_cb, "DuplicateNameTimer");
    auto timing_mw2 = qb::http::timing_middleware<MockTimingSession>(multi_cb, "DuplicateNameTimer");

    // Re-initialize router for this specific test setup in configure_router_and_run
    _router = std::make_unique<qb::http::Router<MockTimingSession>>(); 
    _router->use(timing_mw1);
    _router->use(timing_mw2);
    _router->get("/timed_route", simple_handler(std::chrono::milliseconds(5)));
    _router->compile();
        
    _session->reset();
    _router->route(_session, create_request());

    EXPECT_TRUE(_session->_final_handler_called);
    // Because both middlewares use the same context key ("__TimingMiddleware_StartTime_DuplicateNameTimer"),
    // the second middleware's process() call will overwrite the start time set by the first.
    // When the REQUEST_COMPLETE hook runs, both lifecycle hooks (one for each middleware instance)
    // will be triggered. Both will read the SAME start time (the one set by mw2).
    // Thus, both will calculate and report roughly the same duration: (end_time - start_time_mw2).
    // The callback will be invoked twice.
    EXPECT_EQ(callback_invocation_count, 2);
    ASSERT_EQ(durations_logged.size(), 2);

    if (durations_logged.size() == 2) {
        EXPECT_GE(durations_logged[0].count(), 5);
        EXPECT_GE(durations_logged[1].count(), 5);
        // The durations should be very close as they measure from mw2's start time to hook execution time.
        EXPECT_NEAR(durations_logged[0].count(), durations_logged[1].count(), 5); 
    }
}

TEST_F(TimingMiddlewareTest, TimingWhenHandlerThrowsException) {
    auto timing_mw = qb::http::timing_middleware<MockTimingSession>(_test_timing_callback, "ExceptionTimer");

    qb::http::RouteHandlerFn<MockTimingSession> throwing_handler =
        [](std::shared_ptr<qb::http::Context<MockTimingSession>> ctx) {
        // This handler will complete the context with an error, but also throw.
        // Or, it could just throw and rely on a higher-level error handler to call ctx->complete(ERROR).
        // For TimingMiddleware, what matters is if REQUEST_COMPLETE hook is run by Context/RouterCore.
        ctx->response().status_code = qb::http::status::HTTP_STATUS_INTERNAL_SERVER_ERROR;
        ctx->response().body() = "Handler threw intentionally";
        // No explicit ctx->complete() here, to simulate a raw throw or an error handler doing it.
        // If RouterCore ensures finalize_processing (and thus REQUEST_COMPLETE hooks) on exceptions, timing should work.
        throw std::runtime_error("Intentional exception from handler");
    };

    // Define a simple middleware for error finalization
    class SimpleErrorFinalizerMiddleware : public qb::http::IMiddleware<MockTimingSession> {
    public:
        std::string name() const override { return "SimpleErrorFinalizerMiddleware"; }

        // Corrected handle signature
        void process(std::shared_ptr<qb::http::Context<MockTimingSession>> ctx) override {
            // Assuming status_code_type defaults to 0 or an equivalent state if not explicitly set.
            // If there's a specific "unset" enum member, that should be used.
            // For now, checking against a default-constructed qb::http::status (often 0 for enums).
            if (ctx->response().status_code == qb::http::status{}) { 
                ctx->response().status_code = qb::http::status::HTTP_STATUS_INTERNAL_SERVER_ERROR;
            }
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE); // Ensure completion
        }

        // Added missing cancel method
        void cancel() override {
            // Default empty implementation
        }
    };

    _router = std::make_unique<qb::http::Router<MockTimingSession>>();
    _router->use(timing_mw);
    _router->get("/timed_route_throws", throwing_handler);

    auto error_finalizer_mw = std::make_shared<SimpleErrorFinalizerMiddleware>();
    auto error_task = std::make_shared<qb::http::MiddlewareTask<MockTimingSession>>(error_finalizer_mw, "SimpleErrorFinalizerTask");

    _router->set_error_task_chain({error_task});
    _router->compile();
        
    _session->reset();
    // We need to catch the exception that might propagate from router->route()
    // depending on how RouterCore handles it internally versus its error chain.
    try {
        _router->route(_session, create_request("/timed_route_throws"));
    } catch (const std::runtime_error& e) {
        // Expected if error chain doesn't fully suppress it from propagating from route() call
        EXPECT_STREQ(e.what(), "Intentional exception from handler");
    } catch (...) {
        FAIL() << "Unexpected exception type thrown from router->route()";
    }

    // Crucially, check if the timing callback was invoked, even if an exception occurred.
    // This relies on RouterCore/Context to call REQUEST_COMPLETE hooks in its finalization path.
    ASSERT_TRUE(_session->_last_duration_logged.has_value());
    EXPECT_GE(_session->_last_duration_logged->count(), 0);
    // final_handler_called will be false as the normal handler didn't complete due to exception
    EXPECT_FALSE(_session->_final_handler_called); 
}

// Note on "CompletedRequest": The current TimingMiddleware uses HookPoint::REQUEST_COMPLETE,
// so it inherently times the completed request. This is implicitly tested by other tests.

// Note on "ConcurrentTiming": Testing true concurrency effects on timing would require a more
// complex setup with multiple threads and a way to interleave requests, which is beyond
// the scope of typical unit tests for the middleware logic itself. The current design
// stores start time in context, which is per-request, so it should be safe for concurrency.

// Note on "IntegrationWithComplete": TimingMiddleware relies on the router's complete lifecycle
// to trigger its hook. The existing tests verify it by checking _last_duration_logged.

// --- Additional Test Cases ---

TEST_F(TimingMiddlewareTest, ConstructorThrowsOnNullCallback) {
    // Attempt to create TimingMiddleware directly with a null callback
    // The constructor is expected to throw std::invalid_argument
    EXPECT_THROW({
        qb::http::TimingMiddleware<MockTimingSession> bad_mw(nullptr, "NullCbTimer");
    }, std::invalid_argument);

    // Also test the factory function
    EXPECT_THROW({
        auto bad_mw_factory = qb::http::timing_middleware<MockTimingSession>(nullptr, "NullCbFactoryTimer");
    }, std::invalid_argument);
}

TEST_F(TimingMiddlewareTest, TimingFor404NotFound) {
    auto timing_mw = qb::http::timing_middleware<MockTimingSession>(_test_timing_callback, "NotFoundTimer");

    // Re-initialize router and add only the timing middleware
    _router = std::make_unique<qb::http::Router<MockTimingSession>>();
    _router->use(timing_mw);
    // NO routes are added that would match "/non_existent_route"
    _router->compile();

    _session->reset();
    _router->route(_session, create_request("/non_existent_route"));

    // Even for a 404, the REQUEST_COMPLETE hook should run, and thus timing should occur.
    EXPECT_TRUE(_session->_last_duration_logged.has_value());
    EXPECT_GE(_session->_last_duration_logged->count(), 0);
    // The final handler (if any is configured for 404s) might or might not set _final_handler_called.
    // For this test, we primarily care that timing happened.
    // The default router behavior should result in a 404 status code.
    EXPECT_EQ(_session->get_response_ref().status_code, qb::http::status::HTTP_STATUS_NOT_FOUND);
}

TEST_F(TimingMiddlewareTest, CallbackThrowsException) {
    bool main_callback_invoked = false;
    qb::http::TimingMiddleware<MockTimingSession>::TimingCallback throwing_cb =
        [](const std::chrono::milliseconds& /*duration*/) {
        throw std::runtime_error("Intentional exception from timing callback");
    };

    auto timing_mw_throws = qb::http::timing_middleware<MockTimingSession>(throwing_cb, "ThrowingCallbackTimer");
    
    // We can also add a regular timing middleware to see if its hook is still called
    // if the throwing one executes first (hook order might matter).
    // For simplicity, let's first ensure the app doesn't crash with just the throwing one.

    _router = std::make_unique<qb::http::Router<MockTimingSession>>();
    _router->use(timing_mw_throws);
    _router->get("/timed_route", simple_handler());
    _router->compile();

    _session->reset();

    // The expectation is that the router and middleware handle the callback's exception gracefully
    // and do not let it propagate unhandled out of the route() call, crashing the test/app.
    // The request should still complete, possibly with an internal server error if the hook exception is severe,
    // or simply with the hook being skipped/logged internally.
    EXPECT_NO_THROW({
        _router->route(_session, create_request("/timed_route"));
    });

    // Check if the response was set as expected by the simple_handler, indicating request processing continued
    // somewhat normally past the point where the timing hook would have thrown.
    // This depends on how the router's hook execution handles exceptions from individual hooks.
    // If a hook throwing prevents subsequent processing or sets an error status, this might change.
    // For now, let's assume the simple_handler still completes.
    EXPECT_TRUE(_session->_final_handler_called); 
    EXPECT_EQ(_session->get_response_ref().status_code, qb::http::status::HTTP_STATUS_OK);
    // _last_duration_logged will not be set by the throwing_cb. If we had another non-throwing 
    // timing callback, we could check that.
}

TEST_F(TimingMiddlewareTest, ContextKeyCollisionWrongType) {
    const std::string timer_name = "CollisionTimer";
    const std::string context_key = "__TimingMiddleware_StartTime_" + timer_name;

    // 1. Custom middleware that sets the key to a wrong type (int)
    class WrongTypeSetterMiddleware : public qb::http::IMiddleware<MockTimingSession> {
    public:
        std::string _key_to_set;
        WrongTypeSetterMiddleware(std::string key) : _key_to_set(std::move(key)) {}
        std::string name() const override { return "WrongTypeSetter"; }
        void process(std::shared_ptr<qb::http::Context<MockTimingSession>> ctx) override {
            ctx->set(_key_to_set, 12345); // Set an int, TimingMiddleware expects TimePoint
            ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
        }
        void cancel() override {}
    };

    auto wrong_type_setter_mw = std::make_shared<WrongTypeSetterMiddleware>(context_key);
    auto timing_mw = qb::http::timing_middleware<MockTimingSession>(_test_timing_callback, timer_name);

    _router = std::make_unique<qb::http::Router<MockTimingSession>>();
    _router->use(wrong_type_setter_mw); // This runs first
    _router->use(timing_mw);           // This runs second
    _router->get("/timed_route", simple_handler());
    _router->compile();

    _session->reset();
    _router->route(_session, create_request("/timed_route"));

    // The TimingMiddleware should successfully overwrite the incorrect type and proceed with timing.
    // Therefore, the _test_timing_callback (which sets _last_duration_logged) SHOULD be called.
    EXPECT_TRUE(_session->_last_duration_logged.has_value());
    if (_session->_last_duration_logged.has_value()) {
        EXPECT_GE(_session->_last_duration_logged->count(), 0);
    }
    
    // The request should still complete normally via simple_handler.
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->get_response_ref().status_code, qb::http::status::HTTP_STATUS_OK);
}

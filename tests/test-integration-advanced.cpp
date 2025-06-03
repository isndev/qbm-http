#include <gtest/gtest.h>
#include "../http.h"
#include "../routing/router.h"
#include "../routing/context.h"
#include "../routing/controller.h"
#include "../routing/custom_route.h"
#include "../routing/middleware.h"

#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>
#include <vector>
#include <memory> // For std::shared_ptr
#include <sstream> // For std::ostringstream in query param tests
#include <iomanip> // For std::setfill, std::setw, std::hex

// --- Test Counters ---
std::atomic<int> adv_request_count_server{0};
std::atomic<int> adv_request_count_client{0};
std::atomic<bool> adv_server_ready{false};
std::atomic<int> adv_server_side_assertions{0};
std::atomic<int> adv_expected_server_assertions{0};

// --- Forward Declarations ---
class AdvancedIntegrationServer;

// --- Session Class ---
class AdvancedIntegrationSession : public qb::http::use<AdvancedIntegrationSession>::session<
            AdvancedIntegrationServer> {
public:
    AdvancedIntegrationSession(AdvancedIntegrationServer &server_ref)
        : session(server_ref) {
    }

    // The on(qb::http::protocol::request&& msg) method will be inherited or default-forwarded
    // If custom logic is needed upon receiving a raw protocol message, it can be added here.
    // For now, relying on the base class to forward to router.route().
};

// --- Typedefs for convenience ---
using AdvCtx = qb::http::Context<AdvancedIntegrationSession>;
using AdvController = qb::http::Controller<AdvancedIntegrationSession>;
using AdvCustomRoute = qb::http::ICustomRoute<AdvancedIntegrationSession>;
using AdvMiddleware = qb::http::IMiddleware<AdvancedIntegrationSession>;

// --- Helper for URL encoding (basic version for test) ---
static std::string url_encode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c: value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }
        escaped << std::uppercase;
        escaped << '%' << std::setw(2) << int((unsigned char) c);
        escaped << std::nouppercase;
    }
    return escaped.str();
}

// Helper to get current test name for logging
static std::string GetCurrentTestName() {
    const auto *current_test_info = ::testing::UnitTest::GetInstance()->current_test_info();
    if (current_test_info) {
        return std::string(current_test_info->test_suite_name()) + "." + current_test_info->name();
    }
    return "UNKNOWN_TEST.UNKNOWN_CASE";
}

// --- Custom Middleware Examples ---
class GlobalLoggingMiddleware : public AdvMiddleware {
public:
    std::string name() const override { return "GlobalLoggingMiddleware"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        std::cout << "[GlobalLoggingMiddleware] Request: " << std::to_string(ctx->request().method()) << " " << ctx->
                request().uri().path() << std::endl;
        adv_server_side_assertions++; // Count middleware execution
        ctx->response().set_header("X-Global-Middleware", "Applied");
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }
};

class ApiV1AuthMiddleware : public AdvMiddleware {
public:
    std::string name() const override { return "ApiV1AuthMiddleware"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_server_side_assertions++;
        if (ctx->request().header("Authorization") == "Bearer valid_token_v1") {
            ctx->response().set_header("X-ApiV1-Auth", "TokenValid");
            ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
        } else {
            ctx->response().status() = qb::http::status::UNAUTHORIZED;
            ctx->response().body() = "APIv1: Unauthorized";
            ctx->response().set_header("X-ApiV1-Auth", "TokenInvalidOrMissing");
            ctx->complete();
        }
    }
};

class OrderCheckMiddleware1 : public AdvMiddleware {
public:
    std::string name() const override { return "OrderCheckMiddleware1"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_server_side_assertions++;
        ctx->response().set_header("X-MW-Order", ctx->response().header("X-MW-Order") + "MW1;");
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }
};

class OrderCheckMiddleware2 : public AdvMiddleware {
public:
    std::string name() const override { return "OrderCheckMiddleware2"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_server_side_assertions++;
        ctx->response().set_header("X-MW-Order", ctx->response().header("X-MW-Order") + "MW2;");
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }
};

class OrderCheckMiddleware3ShortCircuit : public AdvMiddleware {
public:
    std::string name() const override { return "OrderCheckMiddleware3ShortCircuit"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_server_side_assertions++;
        ctx->response().set_header("X-MW-Order", ctx->response().header("X-MW-Order") + "MW3SC;");
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Short-circuited by Middleware3!";
        ctx->complete();
    }
};

class ErrorInducingMiddleware : public AdvMiddleware {
public:
    std::string name() const override { return "ErrorInducingMiddleware"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_server_side_assertions++;
        ctx->response().set_header("X-Error-Inducer", "Applied");
        std::cout << "[ErrorInducingMiddleware] Intentionally causing an error for path: " << ctx->request().uri().
                path() << std::endl;
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
    }
};

// --- New Middleware for Additional Tests ---

class AsyncProcessingMiddleware : public AdvMiddleware {
public:
    std::string name() const override { return "AsyncProcessingMiddleware"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_server_side_assertions++;
        ctx->response().set_header("X-Async-MW-Status", "Pending");
        std::cout << "[AsyncProcessingMiddleware] Started for path: " << ctx->request().uri().path() << std::endl;

        auto captured_ctx = ctx;
        qb::io::async::callback([captured_ctx]() {
            std::cout << "[AsyncProcessingMiddleware] Async part executing for path: " << captured_ctx->request().uri().
                    path() << std::endl;
            adv_server_side_assertions++; // Assertion for async part completion
            captured_ctx->response().set_header("X-Async-MW-Status", "Completed");
            captured_ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
        }, 0.01); // Short delay for the async operation
    }
};

class ConditionalContinueMiddleware : public AdvMiddleware {
public:
    std::string name() const override { return "ConditionalContinueMiddleware"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_server_side_assertions++; // Assertion for middleware invocation
        std::string condition = ctx->request().header("X-Test-Condition");

        if (condition == "pass") {
            std::cout << "[ConditionalContinueMiddleware] Condition met. Continuing chain." << std::endl;
            ctx->response().set_header("X-Conditional-Result", "continued");
            ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
        } else {
            std::cout << "[ConditionalContinueMiddleware] Condition NOT met or header missing. Completing early." <<
                    std::endl;
            ctx->response().set_header("X-Conditional-Result", "completed_by_mw");
            ctx->response().status() = qb::http::status::MISCELLANEOUS_PERSISTENT_WARNING; // Custom status for testing
            ctx->response().body() = "Request processing completed by ConditionalContinueMiddleware.";
            ctx->complete();
        }
    }
};

class NestedMW1 : public AdvMiddleware {
public:
    std::string name() const override { return "NestedMW1"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_server_side_assertions++;
        std::string current_order = ctx->response().header("X-Nested-Order");
        ctx->response().set_header("X-Nested-Order", current_order + "NestedMW1;");
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }
};

class NestedMW2 : public AdvMiddleware {
public:
    std::string name() const override { return "NestedMW2"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_server_side_assertions++;
        std::string current_order = ctx->response().header("X-Nested-Order");
        ctx->response().set_header("X-Nested-Order", current_order + "NestedMW2;");
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }
};

class NestedShortCircuitMW : public AdvMiddleware {
public:
    std::string name() const override { return "NestedShortCircuitMW"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_server_side_assertions++;
        std::string current_order = ctx->response().header("X-Nested-Order");
        ctx->response().set_header("X-Nested-Order", current_order + "NestedSC;");
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Short-circuited by NestedShortCircuitMW";
        ctx->complete();
    }
};

// --- Middleware for Nested Structure Test ---
class Level0Middleware : public AdvMiddleware {
public:
    std::string name() const override { return "Level0Middleware"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_server_side_assertions++;
        ctx->response().set_header("X-MW-Trace", ctx->response().header("X-MW-Trace") + "L0;");
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }
};

class Level1GroupMiddleware : public AdvMiddleware {
public:
    std::string name() const override { return "Level1GroupMiddleware"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_server_side_assertions++;
        ctx->response().set_header("X-MW-Trace", ctx->response().header("X-MW-Trace") + "L1G;");
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }
};

class Level2NestedGroupMiddleware : public AdvMiddleware {
public:
    std::string name() const override { return "Level2NestedGroupMiddleware"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_server_side_assertions++;
        ctx->response().set_header("X-MW-Trace", ctx->response().header("X-MW-Trace") + "L2NG;");
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }
};

class Level3ControllerMiddleware : public AdvMiddleware {
public:
    std::string name() const override { return "Level3ControllerMiddleware"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_server_side_assertions++;
        ctx->response().set_header("X-MW-Trace", ctx->response().header("X-MW-Trace") + "L3C;");
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }
};

// --- Custom Route Example ---
class MyCustomRoute : public AdvCustomRoute {
public:
    std::string name() const override { return "MyCustomRoute"; }

    void cancel() override {
    }

    void process(std::shared_ptr<AdvCtx> ctx) override {
        adv_request_count_server++;
        adv_server_side_assertions++;
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Response from MyCustomRoute for path: " + std::string(ctx->request().uri().path());
        ctx->response().set_header("X-Custom-Route-Type", "MyCustomRoute");
        ctx->complete();
    }
};

// --- Controller Examples ---
class DataController : public AdvController {
public:
    DataController(std::string prefix) : _prefix(std::move(prefix)) {
    }

    std::string get_node_name() const override { return "DataController"; }

    void initialize_routes() override {
        this->get("/:id", [this](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            std::string item_id = ctx->path_param("id");
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = _prefix + " Data for item: " + item_id;
            if (item_id == "item123") {
                adv_server_side_assertions++;
            }
            adv_server_side_assertions++;
            ctx->complete();
        });

        this->post("/", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().status() = qb::http::status::CREATED;
            ctx->response().body() = "Data created: " + ctx->request().body().template as<std::string>();
            if (ctx->request().body().template as<std::string>() == "{\"name\":\"test_data\"}") {
                adv_server_side_assertions++;
            }
            ctx->complete();
        });

        this->put("/:id", [this](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++; // Unconditional assertion
            std::string item_id = ctx->path_param("id");
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = _prefix + " Data updated for item: " + item_id;
            if (item_id == "item789" || ctx->request().body().template as<std::string>() ==
                "{\"value\":\"updated_data\"}") {
                // example specific check
                adv_server_side_assertions++;
            }
            ctx->complete();
        });

        this->del("/:id", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++; // Unconditional assertion
            std::string item_id = ctx->path_param("id");
            ctx->response().status() = qb::http::status::NO_CONTENT;
            // No body for NO_CONTENT
            if (item_id == "item789") {
                // example specific check
                adv_server_side_assertions++;
            }
            ctx->complete();
        });
    }

private:
    std::string _prefix;
};

class LegacyController : public AdvController {
public:
    LegacyController() {
    }

    std::string get_node_name() const override { return "LegacyController"; }

    void initialize_routes() override {
        class LegacyCtrlMiddlewareImpl : public AdvMiddleware {
        public:
            std::string name() const override { return "LegacyCtrlMiddlewareImpl"; }

            void cancel() override {
            }

            void process(std::shared_ptr<AdvCtx> ctx) override {
                std::cout << "[LegacyController Middleware] Path: " << ctx->request().uri().path() << std::endl;
                adv_server_side_assertions++;
                ctx->response().set_header("X-Legacy-Ctrl-Middleware", "Applied");
                ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
            }
        };
        this->use(std::make_shared<LegacyCtrlMiddlewareImpl>());

        this->get<MyCustomRoute>("/custom");

        this->get("/async_op", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            auto captured_ctx = ctx;
            qb::io::async::callback([captured_ctx]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                captured_ctx->response().status() = qb::http::status::OK;
                captured_ctx->response().body() = "Async operation completed in LegacyController";
                captured_ctx->response().set_header("X-Legacy-Async", "Done");
                captured_ctx->complete();
            }, 0.0);
        });

        this->get("/error_test", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().status() = qb::http::status::BAD_GATEWAY;
            ctx->response().body() = "LegacyController intentional error";
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });
    }
};

class RootMountedController : public AdvController {
public:
    RootMountedController() {
    }

    std::string get_node_name() const override { return "RootMountedController"; }

    void initialize_routes() override {
        this->get("/status_at_root", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "Root controller says hello!";
            ctx->complete();
        });
    }
};

// --- Controller for Comprehensive HTTP Verb Test ---
class ComprehensiveVerbController : public AdvController {
public:
    ComprehensiveVerbController() {
    }

    std::string get_node_name() const override { return "ComprehensiveVerbController"; }

    void initialize_routes() override {
        // GET /items (List all)
        this->get("/items", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "List of all items";
            ctx->complete();
        });

        // POST /items (Create new)
        this->post("/items", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().status() = qb::http::status::CREATED;
            ctx->response().body() = "Created item with body: " + ctx->request().body().template as<std::string>();
            ctx->complete();
        });

        // GET /items/:id (Read specific)
        this->get("/items/:id", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Item details for: " + ctx->path_param("id");
            ctx->complete();
        });

        // PUT /items/:id (Update specific - full replace)
        this->put("/items/:id", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Updated item " + ctx->path_param("id") + " with: " + ctx->request().body().
                                     template as<std::string>();
            ctx->complete();
        });

        // PATCH /items/:id (Partial update specific)
        this->patch("/items/:id", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Patched item " + ctx->path_param("id") + " with: " + ctx->request().body().
                                     template as<std::string>();
            ctx->complete();
        });

        // DELETE /items/:id (Delete specific)
        this->del("/items/:id", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });

        // HEAD /items (Like GET list, but no body)
        this->head("/items", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            // Body will be stripped by the framework or should be empty
            ctx->response().set_header("X-Head-Info", "Head request for items list");
            ctx->complete();
        });

        // OPTIONS /items (Allowed methods for /items path)
        this->options("/items", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().set_header("Allow", "GET, POST, HEAD, OPTIONS");
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });

        // OPTIONS /items/:id (Allowed methods for /items/:id path)
        this->options("/items/:id", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().set_header("Allow", "GET, PUT, PATCH, DELETE, OPTIONS");
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });
    }
};

// --- Server Class ---
class AdvancedIntegrationServer : public qb::http::use<AdvancedIntegrationServer>::server<AdvancedIntegrationSession> {
public:
    AdvancedIntegrationServer()
        : qb::http::use<AdvancedIntegrationServer>::server<AdvancedIntegrationSession>() {
        std::cout << "Setting up advanced routes for server instance..." << std::endl;

        // Define a custom 404 handler
        qb::http::RouteHandlerFn<AdvancedIntegrationSession> custom_not_found_handler =
                [](std::shared_ptr<AdvCtx> ctx) {
            adv_server_side_assertions++; // For the 404 handler itself
            std::cout << "[CustomNotFoundHandler] Path not found: " << ctx->request().uri().path() << std::endl;
            ctx->response().status() = qb::http::status::NOT_FOUND;
            ctx->response().body() = "Oops! The page you\'re looking for doesn\'t exist here (Custom 404).";
            ctx->response().set_header("X-Custom-404", "Applied");
            ctx->complete();
        };
        this->router().set_not_found_handler(custom_not_found_handler);

        // Define a custom global server error handler
        qb::http::RouteHandlerFn<AdvancedIntegrationSession> custom_global_server_error_handler_fn =
                [](std::shared_ptr<AdvCtx> ctx) {
            adv_server_side_assertions++; // For the global error handler itself
            std::cout << "[CustomGlobalServerErrorHandler] An error was caught. Path: " << ctx->request().uri().path()
                    << std::endl;
            ctx->response().status() = qb::http::status::SERVICE_UNAVAILABLE; // e.g., 503
            ctx->response().body() = "A global server error occurred and was handled by our custom global handler.";
            ctx->response().set_header("X-Global-Error-Handler", "Applied");
            ctx->complete();
        };
        // Wrap the lambda in a RouteLambdaTask
        auto global_error_handler_task = std::make_shared<qb::http::RouteLambdaTask<AdvancedIntegrationSession> >(
            custom_global_server_error_handler_fn, "CustomGlobalServerErrorHandlerTask"
        );
        // Create a list of tasks for the error chain
        std::list<std::shared_ptr<qb::http::IAsyncTask<AdvancedIntegrationSession> > > error_chain_list;
        error_chain_list.push_back(global_error_handler_task);

        // Set the error task chain
        this->router().set_error_task_chain(std::move(error_chain_list));

        // 1. Global Middleware (router level)
        this->router().use<GlobalLoggingMiddleware>(); // This is our baseline, always runs first for matched routes

        // Apply Level0Middleware at router level as well for the nested test
        this->router().use<Level0Middleware>();

        // 2. Basic Root Level GET
        this->router().get("/ping", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "pong";
            ctx->complete();
        });

        this->router().head("/ping", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++; // Count handler invocation
            adv_server_side_assertions++; // Count for this handler logic
            ctx->response().status() = qb::http::status::OK;
            // No body for HEAD requests
            ctx->complete();
        });

        // 3. Route Group: /api/v1
        auto api_v1_group = this->router().group("/api/v1");
        if (api_v1_group == nullptr) { throw std::runtime_error("Failed to create api_v1_group"); }

        api_v1_group->use<ApiV1AuthMiddleware>();

        api_v1_group->get("/status", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "APIv1 Status: Healthy";
            ctx->complete();
        });

        auto data_ctrl = api_v1_group->controller<DataController>("/data", "ControllerPrefix_");
        if (data_ctrl == nullptr) { throw std::runtime_error("Failed to create data_ctrl"); }

        auto legacy_ctrl = this->router().controller<LegacyController>("/legacy");
        if (legacy_ctrl == nullptr) { throw std::runtime_error("Failed to create legacy_ctrl"); }

        this->router().get("/files/*filepath", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            std::string filepath = ctx->path_param("filepath");
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "File path: " + filepath;
            if (filepath == "some/long/path/to/file.txt") {
                adv_server_side_assertions++;
            }
            ctx->complete();
        });

        class AdminCheckMiddlewareImpl : public AdvMiddleware {
        public:
            std::string name() const override { return "AdminCheckMiddlewareImpl"; }

            void cancel() override {
            }

            void process(std::shared_ptr<AdvCtx> ctx) override {
                adv_server_side_assertions++;
                if (ctx->request().header("X-User-Role") == "admin") {
                    ctx->response().set_header("X-Admin-Check", "Passed");
                    ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
                } else {
                    ctx->response().status() = qb::http::status::FORBIDDEN;
                    ctx->response().body() = "Access denied: Admin role required.";
                    ctx->response().set_header("X-Admin-Check", "Failed");
                    ctx->complete();
                }
            }
        };
        auto short_circuit_group = this->router().group("/short_circuit_test/admin_only");
        if (short_circuit_group) {
            short_circuit_group->use<AdminCheckMiddlewareImpl>();
            short_circuit_group->get("/resource", [](std::shared_ptr<AdvCtx> ctx) {
                adv_request_count_server++;
                adv_server_side_assertions++;
                ctx->response().status() = qb::http::status::OK;
                ctx->response().body() = "Admin resource accessed.";
                ctx->complete();
            });
        } else {
            throw std::runtime_error("Failed to create group for /short_circuit_test/admin_only");
        }

        this->router().get("/multi_method_resource", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "GET multi_method";
            ctx->complete();
        });
        this->router().post("/multi_method_resource", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().status() = qb::http::status::CREATED;
            ctx->response().body() = "POST multi_method: " + ctx->request().body().template as<std::string>();
            ctx->complete();
        });
        this->router().put("/multi_method_resource", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "PUT multi_method: " + ctx->request().body().template as<std::string>();
            ctx->complete();
        });
        this->router().del("/multi_method_resource", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });

        auto error_handling_group = this->router().group("/errors_test_group");
        if (error_handling_group) {
            // Create a nested sub-group to apply ErrorInducingMiddleware specifically
            auto nested_error_trigger_group = error_handling_group->group("/sub_cause_error");
            if (nested_error_trigger_group) {
                nested_error_trigger_group->use(std::make_shared<ErrorInducingMiddleware>());
                nested_error_trigger_group->get("/actual", [](std::shared_ptr<AdvCtx> ctx) {
                    adv_request_count_server++; // This main handler should not be reached
                    adv_server_side_assertions++;
                    ctx->response().body() = "This response should be overridden by error.";
                    ctx->complete();
                });
            } else {
                throw std::runtime_error("Failed to create /errors_test_group/sub_cause_error");
            }
        } else {
            throw std::runtime_error("Failed to create /errors_test_group");
        }

        this->router().options("/multi_method_resource", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().set_header("Allow", "GET, POST, PUT, DELETE, OPTIONS");
            ctx->response().status() = qb::http::status::NO_CONTENT; // Or HTTP_STATUS_OK
            ctx->complete();
        });

        this->router().get("/param_test/:value", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            std::string val = ctx->path_param("value");
            ctx->response().body() = "Param value: " + val;
            if (val == "hello world" || val == "path/component" || val == "!@#$%^&*()") {
                adv_server_side_assertions++;
            }
            ctx->complete();
        });

        this->router().get("/query_test", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;

            std::string q_name = ctx->request().uri().query("name", 0, "not_found");
            std::string q_name1 = ctx->request().uri().query("name1", 0, "not_found");
            std::string q_name2 = ctx->request().uri().query("name2", 0, "not_found");
            std::string q_enc = ctx->request().uri().query("encoded_name", 0, "not_found");

            std::string body_str = "name=" + q_name + ";name1=" + q_name1 + ";name2=" + q_name2 + ";encoded_name=" +
                                   q_enc;
            ctx->response().body() = body_str;

            if (q_name == "value" && q_name1 == "not_found") adv_server_side_assertions++;
            if (q_name1 == "value1" && q_name2 == "value2") adv_server_side_assertions++;
            if (q_enc == "encoded value") adv_server_side_assertions++;
            ctx->complete();
        });

        this->router().get("/specific/resource", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Exact: /specific/resource";
            ctx->complete();
        });
        this->router().get("/specific/:id", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Param: /specific/" + ctx->path_param("id");
            ctx->complete();
        });
        this->router().get("/specific/*wildcard_path", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Wildcard: /specific/" + ctx->path_param("wildcard_path");
            ctx->complete();
        });

        auto root_ctrl = this->router().controller<RootMountedController>("");
        if (!root_ctrl) { throw std::runtime_error("Failed to create root_ctrl"); }

        auto mw_chain_group = this->router().group("/mw_chain_test");
        if (!mw_chain_group) { throw std::runtime_error("Failed to create mw_chain_group"); }

        mw_chain_group->use<OrderCheckMiddleware1>();
        mw_chain_group->use<OrderCheckMiddleware2>();
        mw_chain_group->get("/passthrough", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().set_header("X-MW-Order", ctx->response().header("X-MW-Order") + "Handler;");
            ctx->response().body() = "Middleware chain passthrough complete";
            ctx->complete();
        });

        auto mw_short_circuit_group = this->router().group("/mw_short_circuit_test");
        if (!mw_short_circuit_group) { throw std::runtime_error("Failed to create mw_short_circuit_group"); }
        mw_short_circuit_group->use<OrderCheckMiddleware1>();
        mw_short_circuit_group->use<OrderCheckMiddleware2>();
        mw_short_circuit_group->use<OrderCheckMiddleware3ShortCircuit>();
        mw_short_circuit_group->get("/resource", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "SHOULD NOT SEE THIS - Middleware short circuit failed";
            ctx->complete();
        });

        // Create a sub-group for the route that will have ErrorInducingMiddleware
        auto mw_error_test_sub_group = this->router().group("/mw_error_test_sg");
        if (mw_error_test_sub_group) {
            mw_error_test_sub_group->use(std::make_shared<ErrorInducingMiddleware>());
            mw_error_test_sub_group->get("/route", [](std::shared_ptr<AdvCtx> ctx) {
                adv_request_count_server++; // This assertion should ideally not be hit
                adv_server_side_assertions++;
                ctx->response().body() = "This should not be sent if middleware errors.";
                ctx->complete();
            });
        } else {
            throw std::runtime_error("Failed to create /mw_error_test_sg");
        }

        // --- Routes for AsyncMiddlewareTest ---
        auto async_mw_group = this->router().group("/async_mw_test");
        if (async_mw_group) {
            async_mw_group->use<AsyncProcessingMiddleware>();
            async_mw_group->get("/resource", [](std::shared_ptr<AdvCtx> ctx) {
                adv_request_count_server++;
                adv_server_side_assertions++; // Handler assertion
                ctx->response().status() = qb::http::status::OK;
                ctx->response().body() = "Async MW test successful!";
                ctx->complete();
            });
        } else {
            throw std::runtime_error("Failed to create /async_mw_test group");
        }

        // --- Routes for NestedMiddlewareOrderAndShortCircuitTest ---
        auto nested_mw_base_group = this->router().group("/nested_mw");
        if (nested_mw_base_group) {
            nested_mw_base_group->use<NestedMW1>();
            auto nested_mw_outer_group = nested_mw_base_group->group("/outer");
            if (nested_mw_outer_group) {
                nested_mw_outer_group->use<NestedMW2>();
                nested_mw_outer_group->get("/inner/resource", [](std::shared_ptr<AdvCtx> ctx) {
                    adv_request_count_server++;
                    adv_server_side_assertions++; // Handler assertion
                    std::string current_order = ctx->response().header("X-Nested-Order");
                    ctx->response().set_header("X-Nested-Order", current_order + "Handler;");
                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().body() = "Nested middleware passthrough successful!";
                    ctx->complete();
                });
            } else {
                throw std::runtime_error("Failed to create /nested_mw/outer group");
            }
        } else {
            throw std::runtime_error("Failed to create /nested_mw group");
        }

        auto nested_sc_base_group = this->router().group("/nested_sc");
        if (nested_sc_base_group) {
            nested_sc_base_group->use<NestedMW1>(); // Outer middleware
            auto nested_sc_outer_group = nested_sc_base_group->group("/outer");
            if (nested_sc_outer_group) {
                nested_sc_outer_group->use<NestedShortCircuitMW>(); // This should short circuit
                nested_sc_outer_group->use<NestedMW2>(); // This should NOT run
                nested_sc_outer_group->get("/inner/resource", [](std::shared_ptr<AdvCtx> ctx) {
                    adv_request_count_server++; // Should NOT be reached
                    adv_server_side_assertions++;
                    ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                    ctx->response().body() = "SHOULD NOT SEE THIS - Nested SC failed";
                    ctx->complete();
                });
            } else {
                throw std::runtime_error("Failed to create /nested_sc/outer group");
            }
        } else {
            throw std::runtime_error("Failed to create /nested_sc group");
        }

        // --- Route for ConditionalContinueMiddleware Test ---
        auto conditional_mw_group = this->router().group("/conditional_mw_route");
        if (conditional_mw_group) {
            conditional_mw_group->use<ConditionalContinueMiddleware>();
            conditional_mw_group->get("/action", [](std::shared_ptr<AdvCtx> ctx) {
                adv_request_count_server++;
                adv_server_side_assertions++; // Handler assertion
                ctx->response().status() = qb::http::status::OK;
                ctx->response().body() = "Handler reached successfully after conditional MW.";
                ctx->complete();
            });
        } else {
            throw std::runtime_error("Failed to create /conditional_mw_route group");
        }

        // --- Routes for Specificity and Precedence Testing ---
        this->router().get("/specific_first/static_val", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Static: /specific_first/static_val";
            ctx->complete();
        });
        this->router().get("/specific_first/:param", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Param: /specific_first/" + ctx->path_param("param");
            ctx->complete();
        });

        // Define param route first, then static, to check if static is still preferred
        this->router().get("/specific_second/:param", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Param: /specific_second/" + ctx->path_param("param");
            ctx->complete();
        });
        this->router().get("/specific_second/static_val", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Static: /specific_second/static_val";
            ctx->complete();
        });

        this->router().get("/overlap_test/foo/bar", [](std::shared_ptr<AdvCtx> ctx) {
            // More specific
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Static: /overlap_test/foo/bar";
            ctx->complete();
        });
        this->router().get("/overlap_test/*wildcard_path", [](std::shared_ptr<AdvCtx> ctx) {
            // Less specific
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Wildcard: /overlap_test/" + ctx->path_param("wildcard_path");
            ctx->complete();
        });

        auto precedence_group = this->router().group("/precedence_group");
        if (precedence_group) {
            precedence_group->get("/route1", [](std::shared_ptr<AdvCtx> ctx) {
                adv_request_count_server++;
                adv_server_side_assertions++;
                ctx->response().body() = "ParentGroup: /precedence_group/route1";
                ctx->complete();
            });
            auto nested_precedence_group = precedence_group->group("/nested");
            if (nested_precedence_group) {
                // This route is /precedence_group/nested/route1
                nested_precedence_group->get("/route1", [](std::shared_ptr<AdvCtx> ctx) {
                    adv_request_count_server++;
                    adv_server_side_assertions++;
                    ctx->response().body() = "NestedGroup: /precedence_group/nested/route1";
                    ctx->complete();
                });
            } else {
                throw std::runtime_error("Failed to create /precedence_group/nested");
            }
            // Adding a route that looks like the nested one but is at parent level
            // /precedence_group/nested_route1 (distinct from /precedence_group/nested/route1)
            precedence_group->get("/nested_route1", [](std::shared_ptr<AdvCtx> ctx) {
                adv_request_count_server++;
                adv_server_side_assertions++;
                ctx->response().body() = "ParentGroup: /precedence_group/nested_route1";
                ctx->complete();
            });
        } else {
            throw std::runtime_error("Failed to create /precedence_group");
        }

        // --- Routes for Deeply Nested Middleware Propagation Test ---
        class Level3ControllerImpl : public AdvController {
            // Define as inner class or move if used elsewhere
        public:
            Level3ControllerImpl() {
            }

            std::string get_node_name() const override { return "Level3ControllerImpl"; }

            void initialize_routes() override {
                this->use<Level3ControllerMiddleware>();
                this->get("/endpoint", [](std::shared_ptr<AdvCtx> ctx) {
                    adv_request_count_server++;
                    adv_server_side_assertions++; // Handler assertion
                    ctx->response().set_header("X-MW-Trace", ctx->response().header("X-MW-Trace") + "Handler;");
                    ctx->response().body() = "Deeply nested endpoint reached!";
                    ctx->complete();
                });
            }
        };

        auto l1_group = this->router().group("/level1_group");
        if (l1_group) {
            l1_group->use<Level1GroupMiddleware>();
            auto l2_group = l1_group->group("/level2_nested_group");
            if (l2_group) {
                l2_group->use<Level2NestedGroupMiddleware>();
                auto l3_controller = l2_group->controller<Level3ControllerImpl>("/level3_controller");
                if (!l3_controller) {
                    throw std::runtime_error("Failed to mount Level3ControllerImpl");
                }
            } else {
                throw std::runtime_error("Failed to create /level1_group/level2_nested_group");
            }
        } else {
            throw std::runtime_error("Failed to create /level1_group");
        }

        // --- Routes for Wildcard Multi-Segment Behavior Test ---
        this->router().get("/wildcard_multi/static_prefix/foo/bar/baz", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Static: /wildcard_multi/static_prefix/foo/bar/baz";
            ctx->complete();
        });
        this->router().get("/wildcard_multi/static_prefix/*path_param", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Wildcard after static: " + ctx->path_param("path_param");
            ctx->complete();
        });
        this->router().get("/wildcard_multi/*path_param_high", [](std::shared_ptr<AdvCtx> ctx) {
            adv_request_count_server++;
            adv_server_side_assertions++;
            ctx->response().body() = "Higher wildcard: " + ctx->path_param("path_param_high");
            ctx->complete();
        });

        // --- Mount ComprehensiveVerbController ---
        auto comprehensive_ctrl = this->router().controller<ComprehensiveVerbController>("/comprehensive");
        if (!comprehensive_ctrl) {
            throw std::runtime_error("Failed to mount ComprehensiveVerbController");
        }

        std::cout << "Advanced routes configured for server instance." << std::endl;
        this->router().compile();
    }
};


// --- Test Fixture ---
class AdvancedHttpIntegrationTest : public ::testing::Test {
protected:
    std::unique_ptr<AdvancedIntegrationServer> _server;
    std::thread _server_thread;

    void SetUp() override {
        qb::io::async::init();

        adv_request_count_server = 0;
        adv_request_count_client = 0;
        adv_server_side_assertions = 0;
        adv_expected_server_assertions = 0;
        adv_server_ready = false;

        _server = std::make_unique<AdvancedIntegrationServer>();

        _server_thread = std::thread([this]() {
            qb::io::async::init();

            _server->transport().listen_v4(9877);
            _server->start();
            adv_server_ready = true;
            std::cout << "AdvancedIntegrationServer is ready and listening at port 9877 for test: "
                    << GetCurrentTestName()
                    << std::endl;

            while (adv_server_ready.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
            std::cout << "AdvancedIntegrationServer thread finishing for test: "
                    << GetCurrentTestName()
                    << std::endl;
        });

        while (!adv_server_ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    void TearDown() override {
        adv_server_ready = false;
        if (_server_thread.joinable()) {
            _server_thread.join();
        }
        _server.reset();

        std::cout << "Finished test: "
                << GetCurrentTestName()
                << " Client-Requests: " << adv_request_count_client.load()
                << ", Server-Requests: " << adv_request_count_server.load()
                << ", Server-Assertions-Made: " << adv_server_side_assertions.load()
                << ", Server-Assertions-Expected: " << adv_expected_server_assertions.load()
                << std::endl;
    }

    void PerformTestExecution(
        unsigned int cumulative_expected_client_requests,
        unsigned int cumulative_expected_server_assertions,
        unsigned int cumulative_expected_server_handler_invocations,
        const std::function<void()> &client_test_logic) {
        client_test_logic();

        adv_expected_server_assertions = cumulative_expected_server_assertions;

        EXPECT_EQ(cumulative_expected_client_requests, adv_request_count_client.load())
            << "Client request count mismatch for this test block.";

        EXPECT_EQ(cumulative_expected_server_handler_invocations, adv_request_count_server.load())
            << "Server handler invocation count mismatch for this test block. Expected: " <<
 cumulative_expected_server_handler_invocations
            << ", Got: " << adv_request_count_server.load();

        EXPECT_EQ(adv_expected_server_assertions.load(), adv_server_side_assertions.load())
            << "Server side assertion count mismatch for this test block. Expected: " << adv_expected_server_assertions.
load()
            << ", Got: " << adv_server_side_assertions.load();
    }
};

// --- Test Cases ---
TEST_F(AdvancedHttpIntegrationTest, PingAndApiV1Auth) {
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 3,
                                                  /* cumulative_expected_server_assertions */ 3 + 3 + 4,
                                                  // Ping(GL+L0+H) + Unauth(GL+L0+Auth) + Auth(GL+L0+Auth+H)
                                                  /* cumulative_expected_server_handler_invocations */ 1 + 0 + 1,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /ping" << std::endl;
                                                          qb::http::Request request{{"http://localhost:9877/ping"}};
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("pong", response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /api/v1/status (unauthorized)" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/api/v1/status"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_UNAUTHORIZED, response.status());
                                                          EXPECT_EQ("APIv1: Unauthorized",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("TokenInvalidOrMissing",
                                                                    response.header("X-ApiV1-Auth"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /api/v1/status (authorized)" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/api/v1/status"}
                                                          };
                                                          request.add_header("Authorization", "Bearer valid_token_v1");
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("APIv1 Status: Healthy",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("TokenValid", response.header("X-ApiV1-Auth"));
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, DataControllerOperations) {
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 2,
                                                  /* cumulative_expected_server_assertions */
                                                  (1 + 1 + 1 + 1 + 1) + (1 + 1 + 1 + 1 + 1),
                                                  // Global+L0+Auth+DataCtrlGet+SpecificAssertion + Global+L0+Auth+DataCtrlPost+SpecificAssertion
                                                  /* cumulative_expected_server_handler_invocations */ 1 + 1,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /api/v1/data/item123" << std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/api/v1/data/item123"}
                                                          };
                                                          request.add_header("Authorization", "Bearer valid_token_v1");
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("ControllerPrefix_ Data for item: item123",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending POST /api/v1/data" << std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::POST,
                                                              {"http://localhost:9877/api/v1/data"}
                                                          };
                                                          request.add_header("Authorization", "Bearer valid_token_v1");
                                                          // <<< THIS LINE
                                                          request.add_header("Content-Type", "application/json");
                                                          request.body() = "{\"name\":\"test_data\"}";
                                                          auto response = qb::http::POST(request);
                                                          EXPECT_EQ(HTTP_STATUS_CREATED, response.status());
                                                          EXPECT_EQ("Data created: {\"name\":\"test_data\"}",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, LegacyControllerRoutes) {
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 3,
                                                  /* cumulative_expected_server_assertions */
                                                  (1 + 1 + 1 + 1) + (1 + 1 + 1 + 1) + (1 + 1 + 1 + 1 + 1),
                                                  // CustomR:Global+L0+LegacyMW+Handler. AsyncOp:Global+L0+LegacyMW+Handler. ErrorT:Global+L0+LegacyMW+Handler+GlobalErrorH
                                                  /* cumulative_expected_server_handler_invocations */ 1 + 1 + 1,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /legacy/custom" << std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/legacy/custom"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ(
                                                              "Response from MyCustomRoute for path: /legacy/custom",
                                                              response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("Applied",
                                                                    response.header("X-Legacy-Ctrl-Middleware"));
                                                          EXPECT_EQ("MyCustomRoute",
                                                                    response.header("X-Custom-Route-Type"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /legacy/async_op" << std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/legacy/async_op"}
                                                          };
                                                          auto response = qb::http::GET(request, 7.0);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Async operation completed in LegacyController",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("Applied",
                                                                    response.header("X-Legacy-Ctrl-Middleware"));
                                                          EXPECT_EQ("Done", response.header("X-Legacy-Async"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /legacy/error_test" << std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/legacy/error_test"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_SERVICE_UNAVAILABLE, response.status());
                                                          EXPECT_EQ(
                                                              "A global server error occurred and was handled by our custom global handler.",
                                                              response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("Applied",
                                                                    response.header("X-Legacy-Ctrl-Middleware"));
                                                          EXPECT_EQ("Applied",
                                                                    response.header("X-Global-Error-Handler"));
                                                          // Check for global error handler header
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, WildcardAndShortCircuit) {
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 3,
                                                  /* cumulative_expected_server_assertions */
                                                  (1 + 1 + 1 + 1) + (1 + 1 + 1) + (1 + 1 + 1 + 1),
                                                  // File:Global+L0+Handler+Specific. SC-Forbidden:Global+L0+AdminFail. SC-Allowed:Global+L0+AdminOK+Handler
                                                  /* cumulative_expected_server_handler_invocations */ 1 + 0 + 1,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /files/some/long/path/to/file.txt" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/files/some/long/path/to/file.txt"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("File path: some/long/path/to/file.txt",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /short_circuit_test/admin_only/resource (forbidden)"
                                                                  << std::endl;
                                                          qb::http::Request request{
                                                              {
                                                                  "http://localhost:9877/short_circuit_test/admin_only/resource"
                                                              }
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_FORBIDDEN, response.status());
                                                          EXPECT_EQ("Access denied: Admin role required.",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("Failed", response.header("X-Admin-Check"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /short_circuit_test/admin_only/resource (allowed)"
                                                                  << std::endl;
                                                          qb::http::Request request{
                                                              {
                                                                  "http://localhost:9877/short_circuit_test/admin_only/resource"
                                                              }
                                                          };
                                                          request.add_header("X-User-Role", "admin");
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Admin resource accessed.",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("Passed", response.header("X-Admin-Check"));
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}


TEST_F(AdvancedHttpIntegrationTest, MultiMethodResource) {
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 5,
                                                  /* cumulative_expected_server_assertions */
                                                  (1 + 1 + 1) + (1 + 1 + 1) + (1 + 1 + 1) + (1 + 1 + 1) + (1 + 1 + 1),
                                                  // Each: Global+L0+Handler, 404: Global+L0+Custom404
                                                  /* cumulative_expected_server_handler_invocations */
                                                  1 + 1 + 1 + 1 + 0,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /multi_method_resource" << std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/multi_method_resource"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("GET multi_method",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending POST /multi_method_resource" << std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::POST,
                                                              {"http://localhost:9877/multi_method_resource"}
                                                          };
                                                          request.body() = "payload_for_post";
                                                          auto response = qb::http::POST(request);
                                                          EXPECT_EQ(HTTP_STATUS_CREATED, response.status());
                                                          EXPECT_EQ("POST multi_method: payload_for_post",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending PUT /multi_method_resource" << std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::PUT,
                                                              {"http://localhost:9877/multi_method_resource"}
                                                          };
                                                          request.body() = "payload_for_put";
                                                          auto response = qb::http::PUT(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("PUT multi_method: payload_for_put",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending DELETE /multi_method_resource" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::DEL,
                                                              {"http://localhost:9877/multi_method_resource"}
                                                          };
                                                          auto response = qb::http::DEL(request);
                                                          EXPECT_EQ(HTTP_STATUS_NO_CONTENT, response.status());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending PATCH /multi_method_resource" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::PATCH,
                                                              {"http://localhost:9877/multi_method_resource"}
                                                          };
                                                          auto response = qb::http::PATCH(request);
                                                          EXPECT_EQ(HTTP_STATUS_NOT_FOUND, response.status());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          // L0 still runs before 404 chain
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, PathParamEncoding) {
    const std::vector<std::pair<std::string, std::string> > param_test_cases = {
        {"simplevalue", "Param value: simplevalue"},
        {"hello world", "Param value: hello world"},
        {"path/component", "Param value: path/component"},
        {"!@#$%^&*()", "Param value: !@#$%^&*()"}
    };

    // Each case: GlobalMW + L0MW + ParamHandler (unconditional) + SpecificParamAssertion (conditional)
    // "simplevalue": 1+1+1+0 = 3
    // "hello world": 1+1+1+1 = 4
    // "path/component": 1+1+1+1 = 4
    // "!@#$%^&*()": 1+1+1+1 = 4
    // Total: 3+4+4+4 = 15
    PerformTestExecution(
        /* cumulative_expected_client_requests */ param_test_cases.size(),
                                                  /* cumulative_expected_server_assertions */ 15,
                                                  /* cumulative_expected_server_handler_invocations */
                                                  param_test_cases.size(),
                                                  [&]() {
                                                      for (const auto &tc: param_test_cases) {
                                                          std::string encoded_param = url_encode(tc.first);
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /param_test/" << encoded_param <<
                                                                  " (decoded: " << tc.first << ")" << std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/param_test/" + encoded_param}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ(tc.second, response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, QueryParamHandling) {
    // Each: GlobalMW + L0MW + Handler + SpecificQueryAssertion
    // Total assertions = 3 cases * (1+1+1+1) = 3 * 4 = 12
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 3,
                                                  /* cumulative_expected_server_assertions */ 3 * 4,
                                                  /* cumulative_expected_server_handler_invocations */ 3,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /query_test?name=value" << std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/query_test?name=value"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ(
                                                              "name=value;name1=not_found;name2=not_found;encoded_name=not_found",
                                                              response.body().as<std::string>());
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /query_test?name1=value1&name2=value2"
                                                                  << std::endl;
                                                          qb::http::Request request{
                                                              {
                                                                  "http://localhost:9877/query_test?name1=value1&name2=value2"
                                                              }
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ(
                                                              "name=not_found;name1=value1;name2=value2;encoded_name=not_found",
                                                              response.body().as<std::string>());
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::string encoded_query_val = url_encode("encoded value");
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /query_test?encoded_name=" <<
                                                                  encoded_query_val << std::endl;
                                                          qb::http::Request request{
                                                              {
                                                                  "http://localhost:9877/query_test?encoded_name=" +
                                                                  encoded_query_val
                                                              }
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ(
                                                              "name=not_found;name1=not_found;name2=not_found;encoded_name=encoded value",
                                                              response.body().as<std::string>());
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, RoutePrecedence) {
    // Each: GlobalMW + L0MW + Handler
    // Total assertions = 3 cases * (1+1+1) = 3 * 3 = 9
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 3,
                                                  /* cumulative_expected_server_assertions */ 3 * 3,
                                                  /* cumulative_expected_server_handler_invocations */ 3,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /specific/resource (exact)" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/specific/resource"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Exact: /specific/resource",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /specific/myid123 (param)" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/specific/myid123"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Param: /specific/myid123",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /specific/a/b/c (wildcard)" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/specific/a/b/c"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Wildcard: /specific/a/b/c",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, RootMountedControllerAndMiddlewareChain) {
    // RootCtrl: Global+L0+Handler = 3
    // MWChain: Global+L0+MW1+MW2+Handler = 5
    // MWShortCircuit: Global+L0+MW1+MW2+MW3SC = 5
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 3,
                                                  /* cumulative_expected_server_assertions */
                                                  (1 + 1 + 1) + (1 + 1 + 1 + 1 + 1) + (1 + 1 + 1 + 1 + 1),
                                                  /* cumulative_expected_server_handler_invocations */ 1 + 1 + 0,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /status_at_root" << std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/status_at_root"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Root controller says hello!",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /mw_chain_test/passthrough" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/mw_chain_test/passthrough"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Middleware chain passthrough complete",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("MW1;MW2;Handler;", response.header("X-MW-Order"));
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /mw_short_circuit_test/resource" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/mw_short_circuit_test/resource"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Short-circuited by Middleware3!",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          std::string order_check_val = response.header("X-MW-Order");
                                                          EXPECT_TRUE(
                                                              order_check_val.find("MW1;") != std::string::npos);
                                                          EXPECT_TRUE(
                                                              order_check_val.find("MW2;") != std::string::npos);
                                                          EXPECT_TRUE(
                                                              order_check_val.find("MW3SC;") != std::string::npos);
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, NotFoundAndHeadRequests) {
    // 404: GlobalMW + L0MW + Custom404Handler = 3
    // HEAD: GlobalMW + L0MW + PingHandler = 3
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 2,
                                                  /* cumulative_expected_server_assertions */ (1 + 1 + 1) + (1 + 1 + 1),
                                                  /* cumulative_expected_server_handler_invocations */ 0 + 1,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /this/path/does/not/exist" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/this/path/does/not/exist"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_NOT_FOUND, response.status());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("Applied", response.header("X-Custom-404"));
                                                          EXPECT_EQ(
                                                              "Oops! The page you\'re looking for doesn\'t exist here (Custom 404).",
                                                              response.body().as<std::string>());
                                                          adv_request_count_client++;
                                                      } {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending HEAD /ping" << std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::HEAD, {"http://localhost:9877/ping"}
                                                          };
                                                          auto response = qb::http::HEAD(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_TRUE(response.body().as<std::string>().empty());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, DataControllerUpdateDeleteOperations) {
    // PUT OK: Global+L0+Auth+Ctrl+Spec = 5
    // DEL OK: Global+L0+Auth+Ctrl+Spec = 5
    // PUT Unauth: Global+L0+AuthFail = 3
    // DEL Unauth: Global+L0+AuthFail = 3
    // Total = 5 + 5 + 3 + 3 = 16
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 4,
                                                  /* cumulative_expected_server_assertions */ 16,
                                                  /* cumulative_expected_server_handler_invocations */ 1 + 1 + 0 + 0,
                                                  [&]() {
                                                      // PUT Successful
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending PUT /api/v1/data/item789 (authorized)" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::PUT,
                                                              {"http://localhost:9877/api/v1/data/item789"}
                                                          };
                                                          request.add_header("Authorization", "Bearer valid_token_v1");
                                                          request.body() = "{\"value\":\"updated_data\"}";
                                                          auto response = qb::http::PUT(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("ControllerPrefix_ Data updated for item: item789",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("TokenValid", response.header("X-ApiV1-Auth"));
                                                          adv_request_count_client++;
                                                      }
                                                      // DELETE Successful
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending DELETE /api/v1/data/item789 (authorized)"
                                                                  << std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::DEL,
                                                              {"http://localhost:9877/api/v1/data/item789"}
                                                          };
                                                          request.add_header("Authorization", "Bearer valid_token_v1");
                                                          auto response = qb::http::DEL(request);
                                                          EXPECT_EQ(HTTP_STATUS_NO_CONTENT, response.status());
                                                          EXPECT_TRUE(response.body().as<std::string>().empty());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("TokenValid", response.header("X-ApiV1-Auth"));
                                                          adv_request_count_client++;
                                                      }
                                                      // PUT Unauthorized
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending PUT /api/v1/data/item789 (unauthorized)"
                                                                  << std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::PUT,
                                                              {"http://localhost:9877/api/v1/data/item789"}
                                                          };
                                                          request.body() = "{\"value\":\"updated_data_unauth\"}";
                                                          auto response = qb::http::PUT(request);
                                                          EXPECT_EQ(HTTP_STATUS_UNAUTHORIZED, response.status());
                                                          EXPECT_EQ("APIv1: Unauthorized",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("TokenInvalidOrMissing",
                                                                    response.header("X-ApiV1-Auth"));
                                                          adv_request_count_client++;
                                                      }
                                                      // DELETE Unauthorized
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending DELETE /api/v1/data/item789 (unauthorized)"
                                                                  << std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::DEL,
                                                              {"http://localhost:9877/api/v1/data/item789"}
                                                          };
                                                          auto response = qb::http::DEL(request);
                                                          EXPECT_EQ(HTTP_STATUS_UNAUTHORIZED, response.status());
                                                          EXPECT_EQ("APIv1: Unauthorized",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("TokenInvalidOrMissing",
                                                                    response.header("X-ApiV1-Auth"));
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, OptionsRequestTest) {
    // GlobalMW + L0MW + OPTIONS handler = 3
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 1,
                                                  /* cumulative_expected_server_assertions */ 1 + 1 + 1,
                                                  /* cumulative_expected_server_handler_invocations */ 1,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending OPTIONS /multi_method_resource" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::OPTIONS,
                                                              {"http://localhost:9877/multi_method_resource"}
                                                          };
                                                          auto response = qb::http::OPTIONS(request);
                                                          EXPECT_EQ(HTTP_STATUS_NO_CONTENT, response.status());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("GET, POST, PUT, DELETE, OPTIONS",
                                                                    response.header("Allow"));
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, MiddlewareInducedErrorTest) {
    // GlobalLoggingMiddleware + L0 + ErrorInducingMiddleware + CustomGlobalServerErrorHandler
    // Assertions: 1 + 1 + 1 + 1 = 4
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 1,
                                                  /* cumulative_expected_server_assertions */ 1 + 1 + 1 + 1,
                                                  /* cumulative_expected_server_handler_invocations */ 0,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /mw_error_test_sg/route" << std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::GET,
                                                              {"http://localhost:9877/mw_error_test_sg/route"}
                                                          };
                                                          auto response = qb::http::GET(request);

                                                          EXPECT_NE(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("Applied", response.header("X-Error-Inducer"));
                                                          // This one will also be handled by the global error handler, so check its header too.
                                                          EXPECT_EQ("Applied",
                                                                    response.header("X-Global-Error-Handler"));
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, GlobalErrorHandlerForMiddlewareErrorTest) {
    // GlobalLoggingMW + L0MW + ErrorInducingMW + CustomGlobalErrorMW
    // Assertions: 1 + 1 + 1 + 1 = 4
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 1,
                                                  /* cumulative_expected_server_assertions */ 1 + 1 + 1 + 1,
                                                  /* cumulative_expected_server_handler_invocations */ 0,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /mw_error_test_sg/route (expecting global error handler)"
                                                                  << std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::GET,
                                                              {"http://localhost:9877/mw_error_test_sg/route"}
                                                          };
                                                          auto response = qb::http::GET(request);

                                                          EXPECT_EQ(HTTP_STATUS_SERVICE_UNAVAILABLE, response.status());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("Applied", response.header("X-Error-Inducer"));
                                                          EXPECT_EQ("Applied",
                                                                    response.header("X-Global-Error-Handler"));
                                                          EXPECT_EQ(
                                                              "A global server error occurred and was handled by our custom global handler.",
                                                              response.body().as<std::string>());
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

// --- New Test Cases ---

TEST_F(AdvancedHttpIntegrationTest, MethodNotAllowedTest) {
    // GlobalMW + L0MW + Custom404Handler = 3
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 1,
                                                  /* cumulative_expected_server_assertions */ 1 + 1 + 1,
                                                  /* cumulative_expected_server_handler_invocations */ 0,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending PATCH /ping (method not allowed)" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::PATCH, {"http://localhost:9877/ping"}
                                                          };
                                                          auto response = qb::http::PATCH(request);
                                                          EXPECT_EQ(HTTP_STATUS_NOT_FOUND, response.status());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("Applied", response.header("X-Custom-404"));
                                                          EXPECT_EQ(
                                                              "Oops! The page you\'re looking for doesn\'t exist here (Custom 404).",
                                                              response.body().as<std::string>());
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, ConditionalMiddlewareFlowTest) {
    // MW completes: GlobalMW + L0MW + ConditionalMW = 3
    // MW continues: GlobalMW + L0MW + ConditionalMW + Handler = 4
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 2,
                                                  /* cumulative_expected_server_assertions */
                                                  (1 + 1 + 1) + (1 + 1 + 1 + 1),
                                                  /* cumulative_expected_server_handler_invocations */ 0 + 1,
                                                  [&]() {
                                                      // Case 1: Middleware completes the request (condition not met)
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /conditional_mw_route/action (MW completes)"
                                                                  << std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::GET,
                                                              {"http://localhost:9877/conditional_mw_route/action"}
                                                          };
                                                          auto response = qb::http::GET(request);

                                                          EXPECT_EQ(299, response.status());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("completed_by_mw",
                                                                    response.header("X-Conditional-Result"));
                                                          EXPECT_EQ(
                                                              "Request processing completed by ConditionalContinueMiddleware.",
                                                              response.body().as<std::string>());
                                                          adv_request_count_client++;
                                                      }

                                                      // Case 2: Middleware continues to handler (condition met)
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /conditional_mw_route/action (MW continues)"
                                                                  << std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::GET,
                                                              {"http://localhost:9877/conditional_mw_route/action"}
                                                          };
                                                          request.add_header("X-Test-Condition", "pass");
                                                          auto response = qb::http::GET(request);

                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("continued",
                                                                    response.header("X-Conditional-Result"));
                                                          EXPECT_EQ(
                                                              "Handler reached successfully after conditional MW.",
                                                              response.body().as<std::string>());
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, AsyncMiddlewareTest) {
    // GlobalMW + L0MW + AsyncMW (start + complete) + Handler = 1+1+2+1 = 5
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 1,
                                                  /* cumulative_expected_server_assertions */ 1 + 1 + 2 + 1,
                                                  /* cumulative_expected_server_handler_invocations */ 1,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /async_mw_test/resource" << std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::GET,
                                                              {"http://localhost:9877/async_mw_test/resource"}
                                                          };
                                                          auto response = qb::http::GET(request, 5.0);

                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("Completed", response.header("X-Async-MW-Status"));
                                                          EXPECT_EQ("Async MW test successful!",
                                                                    response.body().as<std::string>());
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

TEST_F(AdvancedHttpIntegrationTest, NestedMiddlewareOrderAndShortCircuitTest) {
    // Passthrough: Global + L0 + NMW1 + NMW2 + Handler = 1+1+1+1+1 = 5
    // SC: Global + L0 + NMW1 + NSCMW = 1+1+1+1 = 4
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 2,
                                                  /* cumulative_expected_server_assertions */
                                                  (1 + 1 + 1 + 1 + 1) + (1 + 1 + 1 + 1),
                                                  /* cumulative_expected_server_handler_invocations */ 1 + 0,
                                                  [&]() {
                                                      // Test passthrough
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /nested_mw/outer/inner/resource" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::GET,
                                                              {"http://localhost:9877/nested_mw/outer/inner/resource"}
                                                          };
                                                          auto response = qb::http::GET(request);

                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("NestedMW1;NestedMW2;Handler;",
                                                                    response.header("X-Nested-Order"));
                                                          EXPECT_EQ("Nested middleware passthrough successful!",
                                                                    response.body().as<std::string>());
                                                          adv_request_count_client++;
                                                      }
                                                      // Test short-circuit in nested group
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /nested_sc/outer/inner/resource" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::GET,
                                                              {"http://localhost:9877/nested_sc/outer/inner/resource"}
                                                          };
                                                          auto response = qb::http::GET(request);

                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          EXPECT_EQ("NestedMW1;NestedSC;",
                                                                    response.header("X-Nested-Order"));
                                                          EXPECT_EQ("Short-circuited by NestedShortCircuitMW",
                                                                    response.body().as<std::string>());
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

// --- New Test Cases for Route Specificity and Precedence ---
TEST_F(AdvancedHttpIntegrationTest, RouteSpecificityTest) {
    // Each: GlobalMW + L0MW + Handler = 1+1+1 = 3
    // Total = 7 requests * 3 assertions/req = 21
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 7,
                                                  /* cumulative_expected_server_assertions */ 7 * 3,
                                                  /* cumulative_expected_server_handler_invocations */ 7,
                                                  [&]() {
                                                      // 1. Static vs. Parameter: Static should be preferred
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /specific_first/static_val" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/specific_first/static_val"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Static: /specific_first/static_val",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 2. Parameter fallback
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /specific_first/param_val" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/specific_first/param_val"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Param: /specific_first/param_val",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 3. Static preferred even if defined after parameter sibling
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /specific_second/static_val" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/specific_second/static_val"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Static: /specific_second/static_val",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 4. Static vs. Wildcard: Static (more specific) should be preferred
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /overlap_test/foo/bar" << std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/overlap_test/foo/bar"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Static: /overlap_test/foo/bar",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 5. Wildcard fallback
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /overlap_test/some/other/path" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/overlap_test/some/other/path"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Wildcard: /overlap_test/some/other/path",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 6. Route in Parent Group
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /precedence_group/route1" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/precedence_group/route1"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("ParentGroup: /precedence_group/route1",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 7. Route in Nested Group
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /precedence_group/nested/route1" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              {"http://localhost:9877/precedence_group/nested/route1"}
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("NestedGroup: /precedence_group/nested/route1",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}


// --- End of New Test Cases for Route Specificity and Precedence ---

// --- New Test Case for Nested Structure Middleware Propagation ---
TEST_F(AdvancedHttpIntegrationTest, NestedStructureMiddlewareTest) {
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 1,
                                                  // GlobalLog + L0 + L1G + L2NG + L3C + Handler = 6 assertions
                                                  /* cumulative_expected_server_assertions */ 1 + 1 + 1 + 1 + 1 + 1,
                                                  /* cumulative_expected_server_handler_invocations */ 1,
                                                  [&]() {
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /level1_group/level2_nested_group/level3_controller/endpoint"
                                                                  << std::endl;
                                                          qb::http::Request request{
                                                              {
                                                                  "http://localhost:9877/level1_group/level2_nested_group/level3_controller/endpoint"
                                                              }
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Deeply nested endpoint reached!",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          // Verify the trace header shows correct order of middleware execution
                                                          std::string expected_trace = "L0;L1G;L2NG;L3C;Handler;";
                                                          EXPECT_EQ(expected_trace, response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

// --- End of New Test Case for Nested Structure Middleware Propagation ---

// --- New Test Case for Wildcard Multi-Segment Behavior ---
TEST_F(AdvancedHttpIntegrationTest, WildcardMultiSegmentTest) {
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 4,
                                                  // Each: GlobalLog + L0 + Handler = 3 assertions. Total = 4 * 3 = 12
                                                  /* cumulative_expected_server_assertions */ 4 * (1 + 1 + 1),
                                                  /* cumulative_expected_server_handler_invocations */ 4,
                                                  [&]() {
                                                      // 1. Exact match to the most specific static route
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /wildcard_multi/static_prefix/foo/bar/baz"
                                                                  << std::endl;
                                                          qb::http::Request request{
                                                              {
                                                                  "http://localhost:9877/wildcard_multi/static_prefix/foo/bar/baz"
                                                              }
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Static: /wildcard_multi/static_prefix/foo/bar/baz",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 2. Match wildcard after static prefix (capturing multiple segments)
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /wildcard_multi/static_prefix/segment1/segment2"
                                                                  << std::endl;
                                                          qb::http::Request request{
                                                              {
                                                                  "http://localhost:9877/wildcard_multi/static_prefix/segment1/segment2"
                                                              }
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Wildcard after static: segment1/segment2",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 3. Match higher-level wildcard (capturing static prefix + segments)
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /wildcard_multi/another_static/other_segments/file.txt"
                                                                  << std::endl;
                                                          qb::http::Request request{
                                                              {
                                                                  "http://localhost:9877/wildcard_multi/another_static/other_segments/file.txt"
                                                              }
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ(
                                                              "Higher wildcard: another_static/other_segments/file.txt",
                                                              response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 4. Ensure static prefix route doesn't over-match if a more specific static route exists
                                                      // This is implicitly tested by #1, but an explicit test for a path that *could* match the wildcard but matches a more specific static path before it is good.
                                                      // Our current /wildcard_multi/static_prefix/foo/bar/baz already covers this if /wildcard_multi/static_prefix/*path_param was defined before it.
                                                      // Let's test a path that would match `/wildcard_multi/*path_param_high` if `/wildcard_multi/static_prefix/*path_param` did not exist or was less specific.
                                                      // The path `/wildcard_multi/static_prefix/onlyone` should match `/wildcard_multi/static_prefix/*path_param`
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET /wildcard_multi/static_prefix/onlyone"
                                                                  << std::endl;
                                                          qb::http::Request request{
                                                              {
                                                                  "http://localhost:9877/wildcard_multi/static_prefix/onlyone"
                                                              }
                                                          };
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Wildcard after static: onlyone",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

// --- End of New Test Case for Wildcard Multi-Segment Behavior ---

// --- New Test Case for ComprehensiveVerbController ---
TEST_F(AdvancedHttpIntegrationTest, ComprehensiveVerbControllerTest) {
    PerformTestExecution(
        /* cumulative_expected_client_requests */ 9,
                                                  // Each request: GlobalLog (1) + L0 (1) + Handler (1) = 3 assertions. Total = 9 * 3 = 27
                                                  /* cumulative_expected_server_assertions */ 9 * (1 + 1 + 1),
                                                  /* cumulative_expected_server_handler_invocations */ 9,
                                                  [&]() {
                                                      const std::string base_url =
                                                              "http://localhost:9877/comprehensive/items";

                                                      // 1. GET /items (List)
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET " << base_url << std::endl;
                                                          qb::http::Request request{{base_url}};
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("List of all items",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("Applied", response.header("X-Global-Middleware"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 2. POST /items (Create)
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending POST " << base_url << std::endl;
                                                          qb::http::Request request{qb::http::method::POST, {base_url}};
                                                          request.body() = "new_item_data";
                                                          auto response = qb::http::POST(request);
                                                          EXPECT_EQ(HTTP_STATUS_CREATED, response.status());
                                                          EXPECT_EQ("Created item with body: new_item_data",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 3. GET /items/item123 (Read)
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending GET " << base_url << "/item123" <<
                                                                  std::endl;
                                                          qb::http::Request request{{base_url + "/item123"}};
                                                          auto response = qb::http::GET(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Item details for: item123",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 4. PUT /items/item123 (Update)
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending PUT " << base_url << "/item123" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::PUT, {base_url + "/item123"}
                                                          };
                                                          request.body() = "updated_item_data";
                                                          auto response = qb::http::PUT(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Updated item item123 with: updated_item_data",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 5. PATCH /items/item123 (Partial Update)
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending PATCH " << base_url << "/item123" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::PATCH, {base_url + "/item123"}
                                                          };
                                                          request.body() = "partial_update_data";
                                                          auto response = qb::http::PATCH(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_EQ("Patched item item123 with: partial_update_data",
                                                                    response.body().as<std::string>());
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 6. DELETE /items/item123 (Delete)
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending DELETE " << base_url << "/item123" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::DEL, {base_url + "/item123"}
                                                          };
                                                          auto response = qb::http::DEL(request);
                                                          EXPECT_EQ(HTTP_STATUS_NO_CONTENT, response.status());
                                                          EXPECT_TRUE(response.body().as<std::string>().empty());
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 7. HEAD /items
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending HEAD " << base_url << std::endl;
                                                          qb::http::Request request{qb::http::method::HEAD, {base_url}};
                                                          auto response = qb::http::HEAD(request);
                                                          EXPECT_EQ(HTTP_STATUS_OK, response.status());
                                                          EXPECT_TRUE(response.body().as<std::string>().empty());
                                                          EXPECT_EQ("Head request for items list",
                                                                    response.header("X-Head-Info"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 8. OPTIONS /items
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending OPTIONS " << base_url << std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::OPTIONS, {base_url}
                                                          };
                                                          auto response = qb::http::OPTIONS(request);
                                                          EXPECT_EQ(HTTP_STATUS_NO_CONTENT, response.status());
                                                          EXPECT_EQ("GET, POST, HEAD, OPTIONS",
                                                                    response.header("Allow"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                      // 9. OPTIONS /items/item123
                                                      {
                                                          std::cout << "Client (" << GetCurrentTestName() <<
                                                                  "): Sending OPTIONS " << base_url << "/item123" <<
                                                                  std::endl;
                                                          qb::http::Request request{
                                                              qb::http::method::OPTIONS, {base_url + "/item123"}
                                                          };
                                                          auto response = qb::http::OPTIONS(request);
                                                          EXPECT_EQ(HTTP_STATUS_NO_CONTENT, response.status());
                                                          EXPECT_EQ("GET, PUT, PATCH, DELETE, OPTIONS",
                                                                    response.header("Allow"));
                                                          EXPECT_EQ("L0;", response.header("X-MW-Trace"));
                                                          adv_request_count_client++;
                                                      }
                                                  }
    );
}

// --- End of New Test Case for ComprehensiveVerbController ---


// --- End of New Test Cases for Route Specificity and Precedence ---

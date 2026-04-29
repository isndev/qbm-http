#include <gtest/gtest.h>

#include "../http.h"

#if defined(QBM_HTTP_HAS_HTTP3)

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

class CustomHttp3Session;
using CustomHttp3Server = qb::http3::Server<CustomHttp3Session>;

class CustomHttp3Session
    : public qb::http3::use<CustomHttp3Session>::session<CustomHttp3Server> {
public:
    using Base = qb::http3::use<CustomHttp3Session>::session<CustomHttp3Server>;

    explicit CustomHttp3Session(CustomHttp3Server& server)
        : Base(server) {}
};

class ReuseHttp3Server;

class ReuseHttp3Session
    : public qb::http3::use<ReuseHttp3Session>::session<ReuseHttp3Server> {
public:
    using Base = qb::http3::use<ReuseHttp3Session>::session<ReuseHttp3Server>;

    explicit ReuseHttp3Session(ReuseHttp3Server& server)
        : Base(server) {}
};

class ReuseHttp3Server
    : public qb::http3::use<ReuseHttp3Server>::server<ReuseHttp3Session> {
public:
    std::atomic<int> connected_events{0};

    void on(qb::io::async::quic::event::connected const&) {
        ++connected_events;
    }
};

std::filesystem::path ssl_resource_path(char const *file_name) {
    return std::filesystem::path(__FILE__).parent_path().parent_path().parent_path().parent_path() /
           "qb" / "source" / "io" / "tests" / "system" / "resources" / "ssl" / file_name;
}

std::filesystem::path cert_path() { return ssl_resource_path("cert.pem"); }
std::filesystem::path key_path() { return ssl_resource_path("key.pem"); }

bool certs_available() {
    std::ifstream cert(cert_path());
    std::ifstream key(key_path());
    return cert.good() && key.good();
}

std::filesystem::path homebrew_curl_path() {
    if (auto const *configured = std::getenv("QB_HTTP3_CURL"); configured && *configured) {
        return configured;
    }
    for (auto const& candidate : {
             std::filesystem::path{"/opt/homebrew/opt/curl/bin/curl"},
             std::filesystem::path{"/usr/local/opt/curl/bin/curl"}
         }) {
        if (std::filesystem::exists(candidate)) {
            return candidate;
        }
    }
    return {};
}

std::filesystem::path configured_tool_path(char const *env_name) {
    if (auto const *configured = std::getenv(env_name); configured && *configured) {
        return configured;
    }
    return {};
}

std::string configured_env_value(char const *env_name) {
    if (auto const *configured = std::getenv(env_name); configured && *configured) {
        return configured;
    }
    return {};
}

std::string read_file(std::filesystem::path const& path) {
    std::ifstream in(path);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

struct CommandResult {
    int exit_code = -1;
    bool timed_out = false;
};

CommandResult run_command_with_timeout(std::string const& command,
                                       std::chrono::milliseconds timeout) {
#ifdef _WIN32
    (void)timeout;
    return {std::system(command.c_str()), false};
#else
    const auto pid = fork();
    if (pid < 0) {
        return {-1, false};
    }
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", command.c_str(), static_cast<char *>(nullptr));
        _exit(127);
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    int status = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto result = waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            if (WIFEXITED(status)) {
                return {WEXITSTATUS(status), false};
            }
            if (WIFSIGNALED(status)) {
                return {128 + WTERMSIG(status), false};
            }
            return {-1, false};
        }
        if (result < 0) {
            return {-1, false};
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    kill(pid, SIGTERM);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (waitpid(pid, &status, WNOHANG) == 0) {
        kill(pid, SIGKILL);
    }
    (void)waitpid(pid, &status, 0);
    return {-1, true};
#endif
}

CommandResult run_command_while_pumping(std::string const& command,
                                        std::chrono::milliseconds timeout) {
#ifdef _WIN32
    return run_command_with_timeout(command, timeout);
#else
    const auto pid = fork();
    if (pid < 0) {
        return {-1, false};
    }
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", command.c_str(), static_cast<char *>(nullptr));
        _exit(127);
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    int status = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto result = waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            if (WIFEXITED(status)) {
                return {WEXITSTATUS(status), false};
            }
            if (WIFSIGNALED(status)) {
                return {128 + WTERMSIG(status), false};
            }
            return {-1, false};
        }
        if (result < 0) {
            return {-1, false};
        }
        if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    kill(pid, SIGTERM);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (waitpid(pid, &status, WNOHANG) == 0) {
        kill(pid, SIGKILL);
    }
    (void)waitpid(pid, &status, 0);
    return {-1, true};
#endif
}

void pump_until(std::function<bool()> done, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!done() && std::chrono::steady_clock::now() < deadline) {
        if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

} // namespace

TEST(Http3ClientIntegrationTest, SimpleGetRequest) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().get("/ping", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("x-protocol", "HTTP/3");
        ctx->response().body() = "pong-h3";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31943"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31943");
    client->set_verify_peer(false);

    std::atomic<bool> done{false};
    qb::http::Response response;
    qb::http::Request request{qb::io::uri("https://127.0.0.1:31943/ping")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    EXPECT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("x-protocol"), "HTTP/3");
    EXPECT_EQ(response.body().as<std::string>(), "pong-h3");
    EXPECT_EQ(server_requests.load(), 1);

    client->disconnect();
    server->close();
}

TEST(Http3DualStackIntegrationTest, SameRouteServesHttp2AndHttp3OnSeparateSockets) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http::make_dual_stack_server();
    server->router().get("/shared", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("x-version",
                                   ctx->request().major_version == 3 ? "h3" : "h2");
        ctx->response().body() =
            ctx->request().major_version == 3 ? "shared-over-h3" : "shared-over-h2";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31987"),
                               qb::io::uri("https://127.0.0.1:31988"),
                               cert_path(), key_path()));

    auto http2_client = qb::http2::make_client("https://127.0.0.1:31987");
    http2_client->set_connect_timeout(5.0);
    auto http3_client = qb::http3::make_client("https://127.0.0.1:31988");
    http3_client->set_verify_peer(false);

    std::atomic<bool> h2_done{false};
    std::atomic<bool> h3_done{false};
    qb::http::Response h2_response;
    qb::http::Response h3_response;

    qb::http::Request h2_request{qb::io::uri("/shared")};
    ASSERT_TRUE(http2_client->push_request(std::move(h2_request), [&](qb::http::Response res) {
        h2_response = std::move(res);
        h2_done = true;
    }));
    ASSERT_TRUE(http2_client->connect(nullptr));

    qb::http::Request h3_request{qb::io::uri("/shared")};
    ASSERT_TRUE(http3_client->push_request(std::move(h3_request), [&](qb::http::Response res) {
        h3_response = std::move(res);
        h3_done = true;
    }));

    pump_until([&] { return h2_done.load() && h3_done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(h2_done.load());
    ASSERT_TRUE(h3_done.load());
    EXPECT_EQ(h2_response.status(), qb::http::status::OK);
    EXPECT_EQ(h2_response.header("x-version"), "h2");
    EXPECT_EQ(h2_response.body().as<std::string>(), "shared-over-h2");
    EXPECT_EQ(h3_response.status(), qb::http::status::OK);
    EXPECT_EQ(h3_response.header("x-version"), "h3");
    EXPECT_EQ(h3_response.body().as<std::string>(), "shared-over-h3");

    http2_client->disconnect();
    http3_client->disconnect();
    server->close();
    qb::io::async::listener::current.clear();
}

TEST(Http3DualStackIntegrationTest, ClosingHttp3SideKeepsHttp2SideServing) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http::make_dual_stack_server();
    server->router().get("/h2-only-after-h3-close", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "h2-still-alive";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31989"),
                               qb::io::uri("https://127.0.0.1:31990"),
                               cert_path(), key_path()));

    server->close_http3();

    auto http2_client = qb::http2::make_client("https://127.0.0.1:31989");
    http2_client->set_connect_timeout(5.0);

    std::atomic<bool> done{false};
    qb::http::Response response;
    ASSERT_TRUE(http2_client->push_request(
        qb::http::Request{qb::io::uri("/h2-only-after-h3-close")},
        [&](qb::http::Response res) {
            response = std::move(res);
            done = true;
        }));
    ASSERT_TRUE(http2_client->connect(nullptr));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "h2-still-alive");

    http2_client->disconnect();
    server->close();
    qb::io::async::listener::current.clear();
}

TEST(Http3DualStackIntegrationTest, ClosingHttp2SideKeepsHttp3SideServing) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http::make_dual_stack_server();
    server->router().get("/h3-only-after-h2-close", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "h3-still-alive";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31991"),
                               qb::io::uri("https://127.0.0.1:31992"),
                               cert_path(), key_path()));

    server->close_http2();

    auto http3_client = qb::http3::make_client("https://127.0.0.1:31992");
    http3_client->set_verify_peer(false);

    auto response = qb::http::run_sync(
        http3_client->push_request(qb::http::Request{qb::io::uri("/h3-only-after-h2-close")}));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "h3-still-alive");

    http3_client->disconnect();
    server->close();
    qb::io::async::listener::current.clear();
}

TEST(Http3ClientIntegrationTest, BatchRequestsPreserveOrder) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/item/:id", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = ctx->path_param("id");
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31944"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31944");
    client->set_verify_peer(false);

    std::vector<qb::http::Request> requests;
    for (int i = 0; i < 4; ++i) {
        requests.emplace_back(qb::io::uri("https://127.0.0.1:31944/item/" + std::to_string(i)));
    }

    std::atomic<bool> done{false};
    std::vector<qb::http::Response> responses;
    ASSERT_TRUE(client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> res) {
        responses = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    ASSERT_EQ(responses.size(), 4u);
    for (std::size_t i = 0; i < responses.size(); ++i) {
        EXPECT_EQ(responses[i].status(), qb::http::status::OK);
        EXPECT_EQ(responses[i].body().as<std::string>(), std::to_string(i));
    }

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, BatchKeepsEmptySuccessWhenAnotherRequestTimesOut) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/empty", [](auto ctx) {
        ctx->response().status() = qb::http::status::NO_CONTENT;
        ctx->complete();
    });
    server->router().get("/stall", [](auto) {
        // Keep this stream open so only this request times out.
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31954"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31954");
    client->set_verify_peer(false);
    client->set_request_timeout(0.03);

    std::vector<qb::http::Request> requests;
    requests.emplace_back(qb::io::uri("/empty"));
    requests.emplace_back(qb::io::uri("/stall"));

    std::atomic<bool> done{false};
    std::vector<qb::http::Response> responses;
    ASSERT_TRUE(client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> res) {
        responses = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::NO_CONTENT);
    EXPECT_TRUE(responses[0].body().empty());
    EXPECT_EQ(responses[1].status(), qb::http::status::REQUEST_TIMEOUT);

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 2u);
    EXPECT_EQ(successful, 1u);
    EXPECT_EQ(failed, 1u);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, RelativeUriUsesClientBaseUri) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/relative", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "relative-ok";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31950"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31950");
    client->set_verify_peer(false);

    std::atomic<bool> done{false};
    qb::http::Response response;
    qb::http::Request request{qb::io::uri("/relative")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "relative-ok");

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, RejectsPlainHttpAbsoluteRequestWithoutConnecting) {
    qb::io::async::init();

    auto client = qb::http3::make_client("https://127.0.0.1:32997");
    client->set_connect_timeout(0.01);

    std::atomic<bool> done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(
        qb::http::Request{qb::io::uri("http://127.0.0.1:32997/plain")},
        [&](qb::http::Response res) {
            response = std::move(res);
            done = true;
        }));

    EXPECT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(response.body().as<std::string>(), "HTTP/3 request URI must use https");
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 1u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 1u);
}

TEST(Http3ClientIntegrationTest, BatchRejectsInvalidSchemesAndPreservesOrder) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/valid", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "valid-h3";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31979"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31979");
    client->set_verify_peer(false);

    std::vector<qb::http::Request> requests;
    requests.emplace_back(qb::io::uri("http://127.0.0.1:31979/plain"));
    requests.emplace_back(qb::io::uri("/valid"));
    requests.emplace_back(qb::io::uri("ws://127.0.0.1:31979/ws"));

    std::atomic<bool> done{false};
    std::vector<qb::http::Response> responses;
    ASSERT_TRUE(client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> res) {
        responses = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    ASSERT_EQ(responses.size(), 3u);
    EXPECT_EQ(responses[0].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[0].body().as<std::string>(), "HTTP/3 request URI must use https");
    EXPECT_EQ(responses[1].status(), qb::http::status::OK);
    EXPECT_EQ(responses[1].body().as<std::string>(), "valid-h3");
    EXPECT_EQ(responses[2].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[2].body().as<std::string>(), "HTTP/3 request URI must use https");

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 3u);
    EXPECT_EQ(successful, 1u);
    EXPECT_EQ(failed, 2u);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, PostRequestWithBody) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().post("/echo", [](auto ctx) {
        ctx->response().status() = qb::http::status::CREATED;
        ctx->response().set_header("x-protocol", "HTTP/3");
        ctx->response().body() = ctx->request().body().template as<std::string>();
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31945"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31945");
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::POST, qb::io::uri("https://127.0.0.1:31945/echo")};
    request.body() = "payload-h3";

    std::atomic<bool> done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::CREATED);
    EXPECT_EQ(response.header("x-protocol"), "HTTP/3");
    EXPECT_EQ(response.body().as<std::string>(), "payload-h3");

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, HeadResponseKeepsHeadersButNoBody) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().head("/metadata", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("x-head", "yes");
        ctx->response().body() = "body-that-must-not-be-sent";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31967"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31967");
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::HEAD, qb::io::uri("/metadata")};
    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("x-head"), "yes");
    EXPECT_EQ(response.header("content-length"), std::to_string(std::string("body-that-must-not-be-sent").size()));
    EXPECT_TRUE(response.body().empty());

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, NotModifiedResponseAllowsContentLengthMetadata) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/metadata-304", [](auto ctx) {
        ctx->response().status() = qb::http::status::NOT_MODIFIED;
        ctx->response().set_header("content-length", "123");
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31995"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31995");
    client->set_verify_peer(false);

    auto response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/metadata-304")}));

    EXPECT_EQ(response.status(), qb::http::status::NOT_MODIFIED);
    EXPECT_EQ(response.header("content-length"), "123");
    EXPECT_TRUE(response.body().empty());

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, QueryAndRepeatedHeadersRoundTrip) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/inspect/:id", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("x-path-id", ctx->path_param("id"));
        ctx->response().set_header("x-query-name", ctx->request().query("name"));
        ctx->response().set_header("x-request-header", ctx->request().header("x-custom-header"));
        ctx->response().add_header("set-cookie", "a=1");
        ctx->response().add_header("set-cookie", "b=2");
        ctx->response().body() = "inspect-ok";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31970"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31970");
    client->set_verify_peer(false);

    qb::http::Request request{qb::io::uri("/inspect/42?name=qb")};
    request.set_header("X-CUSTOM-HEADER", "UPPERCASE-KEY");
    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("x-path-id"), "42");
    EXPECT_EQ(response.header("x-query-name"), "qb");
    EXPECT_EQ(response.header("x-request-header"), "UPPERCASE-KEY");
    EXPECT_EQ(response.header("set-cookie", 0), "a=1");
    EXPECT_EQ(response.header("set-cookie", 1), "b=2");
    EXPECT_EQ(response.body().as<std::string>(), "inspect-ok");

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, LargePostBody) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().post("/large", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = std::to_string(ctx->request().body().size());
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31948"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31948");
    client->set_verify_peer(false);

    std::string payload(128 * 1024, 'x');
    qb::http::Request request{qb::http::method::POST, qb::io::uri("https://127.0.0.1:31948/large")};
    request.body() = payload;

    std::atomic<bool> done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), std::to_string(payload.size()));

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, LargeResponseBody) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    std::string payload(160 * 1024, 'r');
    auto server = qb::http3::make_server();
    server->router().get("/large-response", [&payload](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = payload;
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31951"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31951");
    client->set_verify_peer(false);

    std::atomic<bool> done{false};
    qb::http::Response response;
    qb::http::Request request{qb::io::uri("https://127.0.0.1:31951/large-response")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().size(), payload.size());
    EXPECT_EQ(response.body().as<std::string>(), payload);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, RouterNotFoundReturns404) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/known", [](auto ctx) {
        ctx->response().body() = "known";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31946"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31946");
    client->set_verify_peer(false);

    std::atomic<bool> done{false};
    qb::http::Response response;
    qb::http::Request request{qb::io::uri("https://127.0.0.1:31946/missing")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::NOT_FOUND);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ServerErrorResponseIsDelivered) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/error", [](auto ctx) {
        ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
        ctx->response().set_header("x-protocol", "HTTP/3");
        ctx->response().body() = "server error";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31955"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31955");
    client->set_verify_peer(false);

    std::atomic<bool> done{false};
    qb::http::Response response;
    qb::http::Request request{qb::io::uri("/error")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(response.header("x-protocol"), "HTTP/3");
    EXPECT_EQ(response.body().as<std::string>(), "server error");

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, RequestTimeoutReturnsTimeoutResponse) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/stall", [](auto) {
        // Intentionally keep the context open to exercise the client timeout path.
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31947"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31947");
    client->set_verify_peer(false);
    client->set_request_timeout(0.03);

    std::atomic<bool> done{false};
    qb::http::Response response;
    qb::http::Request request{qb::io::uri("https://127.0.0.1:31947/stall")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::REQUEST_TIMEOUT);
    EXPECT_EQ(client->get_active_request_count(), 0u);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ManualDisconnectFailsActiveRequestImmediately) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/stall", [](auto) {
        // Keep the request active until the client disconnects.
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31963"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31963");
    client->set_verify_peer(false);
    client->set_request_timeout(10.0);

    std::atomic<bool> done{false};
    qb::http::Response response;
    qb::http::Request request{qb::io::uri("/stall")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return client->get_active_request_count() == 1u; }, std::chrono::seconds(5));
    ASSERT_EQ(client->get_active_request_count(), 1u);

    client->disconnect();

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_NE(response.body().as<std::string>().find("disconnect"), std::string::npos);
    EXPECT_EQ(client->get_active_request_count(), 0u);

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 1u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 1u);

    server->close();
}

TEST(Http3ClientIntegrationTest, ManualDisconnectFailsBatchOncePerRequest) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/stall/:id", [](auto) {
        // Keep all batch streams active until the client disconnects.
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31965"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31965");
    client->set_verify_peer(false);
    client->set_request_timeout(10.0);

    std::vector<qb::http::Request> requests;
    requests.emplace_back(qb::io::uri("/stall/0"));
    requests.emplace_back(qb::io::uri("/stall/1"));

    std::atomic<bool> done{false};
    std::vector<qb::http::Response> responses;
    ASSERT_TRUE(client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> res) {
        responses = std::move(res);
        done = true;
    }));

    pump_until([&] { return client->get_active_request_count() == 2u; }, std::chrono::seconds(5));
    ASSERT_EQ(client->get_active_request_count(), 2u);

    client->disconnect();

    ASSERT_TRUE(done.load());
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(responses[1].status(), qb::http::status::SERVICE_UNAVAILABLE);

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 2u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 2u);

    server->close();
}

TEST(Http3ClientIntegrationTest, RemoteConnectionCloseFailsActiveRequestWithoutGhostReconnect) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/stall", [](auto) {
        // Keep the request active until the server closes the connection.
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31984"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31984");
    client->set_verify_peer(false);
    client->set_request_timeout(10.0);

    std::atomic<bool> done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/stall")},
                                     [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return client->get_active_request_count() == 1u; }, std::chrono::seconds(5));
    ASSERT_EQ(client->get_active_request_count(), 1u);

    server->close();
    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(client->get_active_request_count(), 0u);
    EXPECT_FALSE(client->is_connected());
    EXPECT_FALSE(client->is_connecting());

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 1u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 1u);

    client->disconnect();
}

TEST(Http3ClientIntegrationTest, MaxConcurrentStreamsQueuesPendingRequests) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    std::vector<std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>>> held_contexts;
    server->router().get("/hold/:id", [&held_contexts](auto ctx) {
        held_contexts.push_back(ctx);
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31964"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31964");
    client->set_verify_peer(false);
    client->set_max_concurrent_streams(1);
    client->set_request_timeout(10.0);

    std::atomic<int> done{0};
    std::vector<qb::http::Response> responses(2);
    for (int i = 0; i < 2; ++i) {
        qb::http::Request request{qb::io::uri("/hold/" + std::to_string(i))};
        ASSERT_TRUE(client->push_request(std::move(request), [&, i](qb::http::Response res) {
            responses[static_cast<std::size_t>(i)] = std::move(res);
            ++done;
        }));
    }

    pump_until([&] { return held_contexts.size() == 1u && client->get_active_request_count() == 1u; },
               std::chrono::seconds(5));
    ASSERT_EQ(held_contexts.size(), 1u);
    EXPECT_EQ(client->get_active_request_count(), 1u);
    EXPECT_EQ(done.load(), 0);

    held_contexts.front()->response().status() = qb::http::status::OK;
    held_contexts.front()->response().body() = "first";
    held_contexts.front()->complete();

    pump_until([&] { return done.load() == 1 && held_contexts.size() == 2u; },
               std::chrono::seconds(5));
    ASSERT_EQ(done.load(), 1);
    ASSERT_EQ(held_contexts.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::OK);
    EXPECT_EQ(responses[0].body().as<std::string>(), "first");
    EXPECT_EQ(client->get_active_request_count(), 1u);

    held_contexts.back()->response().status() = qb::http::status::OK;
    held_contexts.back()->response().body() = "second";
    held_contexts.back()->complete();

    pump_until([&] { return done.load() == 2; }, std::chrono::seconds(5));
    ASSERT_EQ(done.load(), 2);
    EXPECT_EQ(responses[1].status(), qb::http::status::OK);
    EXPECT_EQ(responses[1].body().as<std::string>(), "second");
    EXPECT_EQ(client->get_active_request_count(), 0u);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, RequestTimeoutIncludesPendingBehindConcurrencyLimit) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    std::vector<std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>>> held_contexts;
    server->router().get("/hold/:id", [&held_contexts](auto ctx) {
        held_contexts.push_back(ctx);
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31966"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31966");
    client->set_verify_peer(false);
    client->set_max_concurrent_streams(1);
    client->set_request_timeout(0.03);

    std::atomic<int> done{0};
    std::vector<qb::http::Response> responses(2);
    for (int i = 0; i < 2; ++i) {
        qb::http::Request request{qb::io::uri("/hold/" + std::to_string(i))};
        ASSERT_TRUE(client->push_request(std::move(request), [&, i](qb::http::Response res) {
            responses[static_cast<std::size_t>(i)] = std::move(res);
            ++done;
        }));
    }

    pump_until([&] { return done.load() == 2; }, std::chrono::seconds(5));

    ASSERT_EQ(done.load(), 2);
    EXPECT_GE(held_contexts.size(), 1u);
    EXPECT_LE(held_contexts.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::REQUEST_TIMEOUT);
    EXPECT_EQ(responses[1].status(), qb::http::status::REQUEST_TIMEOUT);
    EXPECT_EQ(client->get_active_request_count(), 0u);

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 2u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 2u);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ConnectTimeoutFailsQueuedRequest) {
    qb::io::async::init();

    auto client = qb::http3::make_client("https://127.0.0.1:32999");
    client->set_verify_peer(false);
    client->set_connect_timeout(0.03);

    std::atomic<bool> connected_callback{false};
    bool connected = true;
    std::string error;
    ASSERT_TRUE(client->connect([&](bool ok, std::string const& message) {
        connected = ok;
        error = message;
        connected_callback = true;
    }));

    pump_until([&] { return connected_callback.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(connected_callback.load());
    EXPECT_FALSE(connected);
    EXPECT_NE(error.find("timeout"), std::string::npos);
    EXPECT_FALSE(client->is_connected());
}

TEST(Http3ClientIntegrationTest, ConnectTimeoutFailsImplicitQueuedRequest) {
    qb::io::async::init();

    auto client = qb::http3::make_client("https://127.0.0.1:32998");
    client->set_verify_peer(false);
    client->set_connect_timeout(0.03);

    std::atomic<bool> done{false};
    qb::http::Response response;
    qb::http::Request request{qb::io::uri("/never")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_NE(response.body().as<std::string>().find("timeout"), std::string::npos);
    EXPECT_FALSE(client->is_connected());
}

TEST(Http3ClientIntegrationTest, AwaiterApiMatchesCallbackApi) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/await", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("x-protocol", "HTTP/3");
        ctx->response().body() = "await-h3";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31952"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31952");
    client->set_verify_peer(false);

    qb::http::Request request{qb::io::uri("/await")};
    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("x-protocol"), "HTTP/3");
    EXPECT_EQ(response.body().as<std::string>(), "await-h3");

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, CoAwaitConnectAndPushRequestInsideCoroutine) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().post("/data", [](auto ctx) {
        ctx->response().status() = qb::http::status::CREATED;
        ctx->response().set_header("x-protocol", "HTTP/3");
        ctx->response().body() = ctx->request().body().template as<std::string>();
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31980"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31980");
    client->set_verify_peer(false);

    bool connected = false;
    qb::http::Response captured;
    qb::io::async::run_sync([&]() -> qb::io::async::task<void> {
        auto result = co_await client->connect();
        connected = result.ok;
        if (!connected) {
            co_return;
        }

        qb::http::Request request{qb::http::method::POST, qb::io::uri("/data")};
        request.set_header("content-type", "text/plain");
        request.body() = "payload-h3-coro";
        captured = co_await client->push_request(std::move(request));
        co_return;
    }());

    ASSERT_TRUE(connected);
    EXPECT_EQ(captured.status(), qb::http::status::CREATED);
    EXPECT_EQ(captured.header("x-protocol"), "HTTP/3");
    EXPECT_EQ(captured.body().as<std::string>(), "payload-h3-coro");

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ServerCleansClosedConnectionsAndAcceptsNewClient) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/again", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "again";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31953"), cert_path(), key_path()));

    {
        auto client = qb::http3::make_client("https://127.0.0.1:31953");
        client->set_verify_peer(false);
        qb::http::Request request{qb::io::uri("/again")};
        auto response = qb::http::run_sync(client->push_request(std::move(request)));
        ASSERT_EQ(response.status(), qb::http::status::OK);
        client->disconnect();
    }

    pump_until([&] {
        qb::io::async::run(EVRUN_NOWAIT);
        return server->stats().active_connections == 0u;
    }, std::chrono::seconds(5));

    EXPECT_EQ(server->stats().active_connections, 0u);
    EXPECT_TRUE(server->is_open());

    auto second = qb::http3::make_client("https://127.0.0.1:31953");
    second->set_verify_peer(false);
    qb::http::Request request{qb::io::uri("/again")};
    auto response = qb::http::run_sync(second->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "again");

    second->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, CustomSessionServerUsesSameRouterApi) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server<CustomHttp3Session>();
    server->router().get("/custom", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("x-session", "custom");
        ctx->response().body() = "custom-h3";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31949"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31949");
    client->set_verify_peer(false);

    std::atomic<bool> done{false};
    qb::http::Response response;
    qb::http::Request request{qb::io::uri("https://127.0.0.1:31949/custom")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("x-session"), "custom");
    EXPECT_EQ(response.body().as<std::string>(), "custom-h3");

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, MultipleConnectCallbacksShareOneHandshake) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/ready", [](auto ctx) {
        ctx->response().body() = "ready";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31956"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31956");
    client->set_verify_peer(false);

    std::atomic<int> callbacks{0};
    bool first_ok = false;
    bool second_ok = false;

    ASSERT_TRUE(client->connect([&](bool ok, std::string const&) {
        first_ok = ok;
        ++callbacks;
    }));
    ASSERT_TRUE(client->connect([&](bool ok, std::string const&) {
        second_ok = ok;
        ++callbacks;
    }));

    pump_until([&] { return callbacks.load() == 2; }, std::chrono::seconds(5));

    EXPECT_EQ(callbacks.load(), 2);
    EXPECT_TRUE(first_ok);
    EXPECT_TRUE(second_ok);
    EXPECT_TRUE(client->is_connected());

    auto connected = qb::http::run_sync(client->connect());
    EXPECT_TRUE(connected);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, SequentialRequestsReuseOneConnection) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = std::make_unique<ReuseHttp3Server>();
    server->router().get("/seq/:id", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = ctx->path_param("id");
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31981"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31981");
    client->set_verify_peer(false);

    qb::http::Request first{qb::io::uri("/seq/first")};
    auto first_response = qb::http::run_sync(client->push_request(std::move(first)));
    ASSERT_EQ(first_response.status(), qb::http::status::OK);
    EXPECT_EQ(first_response.body().as<std::string>(), "first");
    ASSERT_EQ(server->connected_events.load(), 1);
    ASSERT_TRUE(client->is_connected());

    qb::http::Request second{qb::io::uri("/seq/second")};
    auto second_response = qb::http::run_sync(client->push_request(std::move(second)));
    EXPECT_EQ(second_response.status(), qb::http::status::OK);
    EXPECT_EQ(second_response.body().as<std::string>(), "second");
    EXPECT_EQ(server->connected_events.load(), 1);
    EXPECT_TRUE(client->is_connected());

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, BatchAwaiterPreservesMixedResponses) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/ok/:id", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = ctx->path_param("id");
        ctx->complete();
    });
    server->router().get("/empty", [](auto ctx) {
        ctx->response().status() = qb::http::status::NO_CONTENT;
        ctx->complete();
    });
    server->router().get("/error", [](auto ctx) {
        ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
        ctx->response().body() = "boom";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31957"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31957");
    client->set_verify_peer(false);

    std::vector<qb::http::Request> requests;
    requests.emplace_back(qb::io::uri("/ok/1"));
    requests.emplace_back(qb::io::uri("/empty"));
    requests.emplace_back(qb::io::uri("/missing"));
    requests.emplace_back(qb::io::uri("/error"));

    auto responses = qb::http::run_sync(client->push_requests(std::move(requests)));

    ASSERT_EQ(responses.size(), 4u);
    EXPECT_EQ(responses[0].status(), qb::http::status::OK);
    EXPECT_EQ(responses[0].body().as<std::string>(), "1");
    EXPECT_EQ(responses[1].status(), qb::http::status::NO_CONTENT);
    EXPECT_TRUE(responses[1].body().empty());
    EXPECT_EQ(responses[2].status(), qb::http::status::NOT_FOUND);
    EXPECT_EQ(responses[3].status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(responses[3].body().as<std::string>(), "boom");

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, MultipleClientsCanUseOneServerConcurrently) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().get("/client/:id", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = ctx->path_param("id");
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31958"), cert_path(), key_path()));

    std::vector<std::shared_ptr<qb::http3::Client>> clients;
    std::vector<qb::http::Response> responses(3);
    std::atomic<int> done{0};

    for (int i = 0; i < 3; ++i) {
        auto client = qb::http3::make_client("https://127.0.0.1:31958");
        client->set_verify_peer(false);
        qb::http::Request request{qb::io::uri("/client/" + std::to_string(i))};
        ASSERT_TRUE(client->push_request(std::move(request), [&, i](qb::http::Response response) {
            responses[static_cast<std::size_t>(i)] = std::move(response);
            ++done;
        }));
        clients.push_back(std::move(client));
    }

    pump_until([&] { return done.load() == 3; }, std::chrono::seconds(5));

    ASSERT_EQ(done.load(), 3);
    for (std::size_t i = 0; i < responses.size(); ++i) {
        EXPECT_EQ(responses[i].status(), qb::http::status::OK);
        EXPECT_EQ(responses[i].body().as<std::string>(), std::to_string(i));
    }
    EXPECT_EQ(server_requests.load(), 3);

    for (auto& client : clients) {
        client->disconnect();
    }
    server->close();
}

TEST(Http3ClientIntegrationTest, ServerRejectsRequestBodyOverLimit) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->set_max_body_size(8);
    server->router().post("/limited", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = std::to_string(ctx->request().body().size());
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31959"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31959");
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::POST, qb::io::uri("/limited")};
    request.body() = std::string(64, 'x');

    std::atomic<bool> done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_NE(response.status(), qb::http::status::OK);
    EXPECT_EQ(client->get_active_request_count(), 0u);
    EXPECT_TRUE(server->is_open());

    auto second = qb::http3::make_client("https://127.0.0.1:31959");
    second->set_verify_peer(false);
    qb::http::Request ok_request{qb::http::method::POST, qb::io::uri("/limited")};
    ok_request.body() = "ok";
    auto ok_response = qb::http::run_sync(second->push_request(std::move(ok_request)));
    EXPECT_EQ(ok_response.status(), qb::http::status::OK);
    EXPECT_EQ(ok_response.body().as<std::string>(), "2");

    client->disconnect();
    second->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ClientRejectsResponseBodyOverLimit) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/too-large", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = std::string(64, 'r');
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31960"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31960");
    client->set_verify_peer(false);
    client->set_max_body_size(8);

    std::atomic<bool> done{false};
    qb::http::Response response;
    qb::http::Request request{qb::io::uri("/too-large")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_NE(response.status(), qb::http::status::OK);
    EXPECT_EQ(client->get_active_request_count(), 0u);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ServerRejectsRequestContentLengthMismatch) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().post("/length", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "accepted";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31961"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31961");
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::POST, qb::io::uri("/length")};
    request.set_header("content-length", "1");
    request.body() = "abc";

    std::atomic<bool> done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_NE(response.status(), qb::http::status::OK);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ClientRejectsOutgoingRequestContentLengthMismatchBeforeRouter) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().post("/length", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().body() = "unexpected";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31996"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31996");
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::POST, qb::io::uri("/length")};
    request.set_header("content-length", "1");
    request.body() = "abc";

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(server_requests.load(), 0);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ClientRejectsOutgoingRequestContentLengthWithOWSBeforeRouter) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().post("/length-ows", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = ctx->request().body().template as<std::string>();
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31997"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31997");
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::POST, qb::io::uri("/length-ows")};
    request.set_header("content-length", " 3\t");
    request.body() = "abc";

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(server_requests.load(), 0);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ClientRejectsResponseContentLengthMismatch) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/bad-length", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("content-length", "1");
        ctx->response().body() = "abc";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31962"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31962");
    client->set_verify_peer(false);

    std::atomic<bool> done{false};
    qb::http::Response response;
    qb::http::Request request{qb::io::uri("/bad-length")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_NE(response.status(), qb::http::status::OK);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ClientRejectsOversizedOutgoingHeader) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().get("/guarded", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().body() = "unexpected";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31968"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31968");
    client->set_verify_peer(false);

    qb::http::Request request{qb::io::uri("/guarded")};
    request.set_header("x-too-large", std::string(qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'v'));

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(server_requests.load(), 0);

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 1u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 1u);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ServerResetsStreamForOversizedOutgoingHeader) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/bad-response", [](auto ctx) {
        ctx->response().set_header(
            "x-too-large",
            std::string(qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'v'));
        ctx->response().body() = "not sent";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31969"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31969");
    client->set_verify_peer(false);

    qb::http::Request request{qb::io::uri("/bad-response")};
    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_TRUE(server->is_open());

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, GracefulShutdownClosesCurrentConnectionOnly) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/ping", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "pong-before-shutdown";
        ctx->complete();
    });
    server->router().get("/again", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "new-connection-ok";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31971"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31971");
    client->set_verify_peer(false);
    auto response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/ping")}));
    ASSERT_EQ(response.status(), qb::http::status::OK);
    ASSERT_TRUE(client->is_connected());

    server->graceful_shutdown();
    pump_until([&] { return !client->is_connected(); }, std::chrono::seconds(5));
    EXPECT_FALSE(client->is_connected());

    auto second_client = qb::http3::make_client("https://127.0.0.1:31971");
    second_client->set_verify_peer(false);
    auto second = qb::http::run_sync(
        second_client->push_request(qb::http::Request{qb::io::uri("/again")}));
    EXPECT_EQ(second.status(), qb::http::status::OK);
    EXPECT_EQ(second.body().as<std::string>(), "new-connection-ok");

    client->disconnect();
    second_client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, GracefulShutdownWaitsForActiveAsyncContext) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    server->router().get("/delayed", [&](auto ctx) {
        held_context = ctx;
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31982"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31982");
    client->set_verify_peer(false);

    std::atomic<bool> done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/delayed")},
                                     [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    pump_until([&] { return held_context != nullptr; }, std::chrono::seconds(5));
    ASSERT_NE(held_context, nullptr);
    ASSERT_TRUE(client->is_connected());

    server->graceful_shutdown();
    for (int i = 0; i < 20; ++i) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_TRUE(client->is_connected());
    EXPECT_FALSE(done.load());

    held_context->response().status() = qb::http::status::OK;
    held_context->response().body() = "delayed-ok";
    held_context->complete();
    held_context.reset();

    pump_until([&] { return done.load() && !client->is_connected(); }, std::chrono::seconds(5));
    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "delayed-ok");
    EXPECT_FALSE(client->is_connected());

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, CancelActiveRequestResetsStreamAndCompletesCallback) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/stall", [](auto) {
        // Keep the stream open until the client cancels it.
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31972"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31972");
    client->set_verify_peer(false);
    client->set_request_timeout(10.0);

    std::atomic<bool> done{false};
    qb::http::Response response;
    auto id = client->push_request_with_id(qb::http::Request{qb::io::uri("/stall")},
                                           [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    });
    ASSERT_NE(id, 0u);

    pump_until([&] { return client->get_active_request_count() == 1; }, std::chrono::seconds(5));
    ASSERT_TRUE(client->cancel_request(id, "manual cancel"));
    pump_until([&] { return done.load(); }, std::chrono::seconds(5));

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::CLIENT_CLOSED_REQUEST);
    EXPECT_EQ(response.body().as<std::string>(), "manual cancel");

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, CancelPendingRequestCompletesWithoutOpeningStream) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    std::atomic<int> fast_requests{0};
    server->router().get("/stall", [](auto) {
        // Keep the first stream active so the second request remains queued.
    });
    server->router().get("/fast", [&fast_requests](auto ctx) {
        ++fast_requests;
        ctx->response().body() = "unexpected";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31973"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31973");
    client->set_verify_peer(false);
    client->set_max_concurrent_streams(1);
    client->set_request_timeout(10.0);

    std::atomic<bool> first_done{false};
    auto first = client->push_request_with_id(qb::http::Request{qb::io::uri("/stall")},
                                              [&](qb::http::Response) {
        first_done = true;
    });
    ASSERT_NE(first, 0u);

    std::atomic<bool> second_done{false};
    qb::http::Response second_response;
    auto second = client->push_request_with_id(qb::http::Request{qb::io::uri("/fast")},
                                               [&](qb::http::Response response) {
        second_response = std::move(response);
        second_done = true;
    });
    ASSERT_NE(second, 0u);

    pump_until([&] { return client->get_active_request_count() == 1; }, std::chrono::seconds(5));
    ASSERT_TRUE(client->cancel_request(second, "pending cancel"));
    pump_until([&] { return second_done.load(); }, std::chrono::seconds(5));

    EXPECT_FALSE(first_done.load());
    EXPECT_TRUE(second_done.load());
    EXPECT_EQ(second_response.status(), qb::http::status::CLIENT_CLOSED_REQUEST);
    EXPECT_EQ(second_response.body().as<std::string>(), "pending cancel");
    EXPECT_EQ(fast_requests.load(), 0);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ResponseTrailersAreDeliveredAsHeaders) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/trailers", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("trailer", "x-checksum");
        ctx->response().set_header("x-checksum", "response-trailer");
        ctx->response().body() = "body-with-trailer";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31974"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31974");
    client->set_verify_peer(false);

    auto response = qb::http::run_sync(
        client->push_request(qb::http::Request{qb::io::uri("/trailers")}));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "body-with-trailer");
    EXPECT_EQ(response.header("x-checksum"), "response-trailer");

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, RequestTrailersAreDeliveredToRouter) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().post("/trailers", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = ctx->request().header("x-client-checksum");
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31975"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31975");
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::POST, qb::io::uri("/trailers")};
    request.set_header("trailer", "x-client-checksum");
    request.set_header("x-client-checksum", "request-trailer");
    request.body() = "payload";

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "request-trailer");

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ClientRejectsForbiddenOutgoingRequestTrailer) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().post("/forbidden-trailer", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().body() = "unexpected";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31976"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31976");
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::POST, qb::io::uri("/forbidden-trailer")};
    request.set_header("trailer", "content-length");
    request.set_header("content-length", "7");
    request.body() = "payload";

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(server_requests.load(), 0);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ClientRejectsForbiddenOutgoingRequestHeader) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().get("/forbidden-header", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().body() = "unexpected";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31985"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31985");
    client->set_verify_peer(false);

    qb::http::Request request{qb::io::uri("/forbidden-header")};
    request.set_header("connection", "close");

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(server_requests.load(), 0);

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ServerRejectsForbiddenOutgoingResponseTrailer) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/forbidden-trailer", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("trailer", "content-length");
        ctx->response().set_header("content-length", "3");
        ctx->response().body() = "abc";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31977"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31977");
    client->set_verify_peer(false);

    auto response = qb::http::run_sync(
        client->push_request(qb::http::Request{qb::io::uri("/forbidden-trailer")}));

    EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_TRUE(server->is_open());

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, ServerRejectsForbiddenOutgoingResponseHeader) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/forbidden-header", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("connection", "close");
        ctx->response().body() = "unexpected";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31986"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31986");
    client->set_verify_peer(false);

    auto response = qb::http::run_sync(
        client->push_request(qb::http::Request{qb::io::uri("/forbidden-header")}));

    EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_TRUE(server->is_open());

    client->disconnect();
    server->close();
}

TEST(Http3ClientIntegrationTest, LifecycleHooksFollowHttpSessionSemantics) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    std::atomic<int> pre_response{0};
    std::atomic<int> post_response{0};
    std::atomic<int> request_complete{0};

    server->router().get("/hooks", [&](auto ctx) {
        ctx->add_lifecycle_hook([&](auto& hook_ctx, qb::http::HookPoint point) {
            if (point == qb::http::HookPoint::PRE_RESPONSE_SEND) {
                ++pre_response;
                hook_ctx.response().set_header("x-hook-pre", "1");
            } else if (point == qb::http::HookPoint::POST_RESPONSE_SEND) {
                ++post_response;
            } else if (point == qb::http::HookPoint::REQUEST_COMPLETE) {
                ++request_complete;
            }
        });
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "hooked";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31983"), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://127.0.0.1:31983");
    client->set_verify_peer(false);

    qb::http::Request request{qb::io::uri("/hooks")};
    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    pump_until([&] {
        return post_response.load() == 1 && request_complete.load() == 1;
    }, std::chrono::seconds(5));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "hooked");
    EXPECT_EQ(response.header("x-hook-pre"), "1");
    EXPECT_EQ(pre_response.load(), 1);
    EXPECT_EQ(post_response.load(), 1);
    EXPECT_EQ(request_complete.load(), 1);

    client->disconnect();
    server->close();
}

TEST(Http3InteropTest, HomebrewCurlCanCallQbHttp3ServerWhenAvailable) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }
    if (!std::filesystem::exists(homebrew_curl_path())) {
        GTEST_SKIP() << "Homebrew curl with HTTP/3 support is unavailable";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/interop", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("content-type", "text/plain");
        ctx->response().body() = "curl-h3-ok";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31978"), cert_path(), key_path()));

    const auto base = std::filesystem::temp_directory_path() /
                      ("qb-http3-curl-" + std::to_string(
                          std::chrono::steady_clock::now().time_since_epoch().count()));
    const auto body_path = base.string() + ".body";
    const auto code_path = base.string() + ".code";
    const auto err_path = base.string() + ".err";

    const auto command = "\"" + homebrew_curl_path().string() + "\""
        " --http3-only --insecure --silent --show-error --max-time 5"
        " --output \"" + body_path + "\""
        " --write-out \"%{http_code}\""
        " https://127.0.0.1:31978/interop"
        " > \"" + code_path + "\""
        " 2> \"" + err_path + "\"";

    const auto result = run_command_while_pumping(command, std::chrono::seconds(6));

    const auto body = read_file(body_path);
    const auto code = read_file(code_path);
    const auto err = read_file(err_path);

    std::filesystem::remove(body_path);
    std::filesystem::remove(code_path);
    std::filesystem::remove(err_path);

    EXPECT_FALSE(result.timed_out) << err;
    EXPECT_EQ(result.exit_code, 0) << err;
    EXPECT_EQ(code, "200") << err;
    EXPECT_EQ(body, "curl-h3-ok");

    server->close();
}

TEST(Http3InteropTest, ConfiguredNghttp3ClientCanCallQbHttp3Server) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }
    const auto client_tool = configured_tool_path("QB_HTTP3_NGHTTP3_CLIENT");
    if (client_tool.empty() || !std::filesystem::exists(client_tool)) {
        GTEST_SKIP() << "Set QB_HTTP3_NGHTTP3_CLIENT to enable nghttp3-client interop";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/nghttp3", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("content-type", "text/plain");
        ctx->response().body() = "nghttp3-client-ok";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31993"), cert_path(), key_path()));

    const auto base = std::filesystem::temp_directory_path() /
                      ("qb-http3-nghttp3-client-" + std::to_string(
                          std::chrono::steady_clock::now().time_since_epoch().count()));
    const auto out_path = base.string() + ".out";
    const auto err_path = base.string() + ".err";

    const auto command = "\"" + client_tool.string() + "\""
        " https://127.0.0.1:31993/nghttp3"
        " > \"" + out_path + "\""
        " 2> \"" + err_path + "\"";

    const auto result = run_command_while_pumping(command, std::chrono::seconds(6));

    const auto out = read_file(out_path);
    const auto err = read_file(err_path);
    std::filesystem::remove(out_path);
    std::filesystem::remove(err_path);

    EXPECT_FALSE(result.timed_out) << err;
    EXPECT_EQ(result.exit_code, 0) << err;
    EXPECT_NE(out.find("nghttp3-client-ok"), std::string::npos) << err;

    server->close();
}

TEST(Http3InteropTest, ConfiguredH3SpecCanProbeQbHttp3Server) {
    if (!certs_available()) {
        GTEST_SKIP() << "test TLS certificates are unavailable";
    }
    const auto h3spec_tool = configured_tool_path("QB_HTTP3_H3SPEC");
    if (h3spec_tool.empty() || !std::filesystem::exists(h3spec_tool)) {
        GTEST_SKIP() << "Set QB_HTTP3_H3SPEC to enable h3spec interop";
    }

    qb::io::async::init();

    auto server = qb::http3::make_server();
    server->router().get("/", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "h3spec-ok";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri("https://127.0.0.1:31994"), cert_path(), key_path()));

    const auto base = std::filesystem::temp_directory_path() /
                      ("qb-http3-h3spec-" + std::to_string(
                          std::chrono::steady_clock::now().time_since_epoch().count()));
    const auto out_path = base.string() + ".out";
    const auto err_path = base.string() + ".err";

    const auto command = "\"" + h3spec_tool.string() + "\""
        " -host 127.0.0.1 -port 31994 -insecure"
        " > \"" + out_path + "\""
        " 2> \"" + err_path + "\"";

    const auto result = run_command_while_pumping(command, std::chrono::seconds(20));

    const auto out = read_file(out_path);
    const auto err = read_file(err_path);
    std::filesystem::remove(out_path);
    std::filesystem::remove(err_path);

    EXPECT_FALSE(result.timed_out) << out << err;
    EXPECT_EQ(result.exit_code, 0) << out << err;

    server->close();
}

TEST(Http3InteropTest, QbHttp3ClientCanCallConfiguredExternalServer) {
    const auto target_url = configured_env_value("QB_HTTP3_EXTERNAL_SERVER_URL");
    if (target_url.empty()) {
        GTEST_SKIP() << "Set QB_HTTP3_EXTERNAL_SERVER_URL to enable external HTTP/3 server interop";
    }

    qb::io::async::init();

    qb::io::uri target{target_url};
    ASSERT_EQ(target.scheme(), "https");
    ASSERT_FALSE(target.host().empty());

    std::string base = "https://" + std::string(target.host());
    if (!target.port().empty()) {
        base.push_back(':');
        base += target.port();
    }

    auto client = qb::http3::make_client(base);
    client->set_connect_timeout(5.0);
    client->set_request_timeout(5.0);
    if (configured_env_value("QB_HTTP3_EXTERNAL_INSECURE") == "1") {
        client->set_verify_peer(false);
    }

    auto response = qb::http::run_sync(
        client->push_request(qb::http::Request{std::move(target)}));

    const auto expected_status = configured_env_value("QB_HTTP3_EXTERNAL_EXPECT_STATUS");
    if (!expected_status.empty()) {
        EXPECT_EQ(response.status().code(), std::stoi(expected_status));
    } else {
        EXPECT_GE(response.status().code(), 200);
        EXPECT_LT(response.status().code(), 500);
    }

    const auto expected_body = configured_env_value("QB_HTTP3_EXTERNAL_EXPECT_BODY");
    if (!expected_body.empty()) {
        EXPECT_NE(response.body().as<std::string>().find(expected_body), std::string::npos);
    }

    client->disconnect();
}

#endif // QBM_HTTP_HAS_HTTP3

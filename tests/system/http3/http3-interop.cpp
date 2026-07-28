/**
 * @file qbm/http/tests/system/http3/http3-interop.cpp
 * @brief System tier (label: interop): HTTP/3 cross-implementation interop probes.
 *
 * Unlike @c http3-loopback.cpp, these tests fork an EXTERNAL HTTP/3 tool against
 * the qb server (a curl built with HTTP/3, an nghttp3 client, h3spec) or drive
 * the qb client against an external HTTP/3 server. They are the only genuinely
 * "needs an outside process" cases in the HTTP/3 suite, so they are isolated
 * here under the @c interop label for an opt-in CI lane.
 *
 * Each test @c GTEST_SKIPs cleanly when its tool / env var is absent — this is
 * legitimate environmental gating of an optional external dependency, not the
 * cert-missing skip that the loopback tier forbids. The TLS cert itself remains
 * a HARD prerequisite (via @c shared/ssl_test_resource.h) for the server-side
 * probes; the client-vs-external-server probe needs no local cert and is gated
 * solely on @c QB_HTTP3_EXTERNAL_SERVER_URL (it never touches the network unless
 * the operator explicitly points it at a server).
 *
 * The @c QBM_HTTP_HAS_HTTP3 gate (SSL ∧ QUIC ∧ libnghttp3) is retained.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include "../http.h"

#if defined(QBM_HTTP_HAS_HTTP3)

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>

#include <qb/system/parse.h>

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

#ifndef _WIN32
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace std::chrono_literals;

namespace {
using qb::http::test::ephemeral_udp_port;

std::filesystem::path
cert_path() {
    return qb::http::test::ssl_cert_path();
}
std::filesystem::path
key_path() {
    return qb::http::test::ssl_key_path();
}
using qb::http::test::certs_available;
using qb::http::test::ephemeral_udp_port;

std::string
https_origin(std::uint16_t port) {
    return "https://127.0.0.1:" + std::to_string(port);
}

// Runs "<curl_cmd> --version" and reports whether that curl was built with
// HTTP/3 support (its "Features:" line then contains "HTTP3"). curl_cmd is a
// ready-to-run shell token (a quoted path, or a bare "curl"/"curl.exe" resolved
// via PATH). Cross-platform: the stock Windows curl uses Schannel (no HTTP/3),
// so this correctly returns false there.
bool
curl_command_has_http3(std::string const &curl_cmd) {
    const auto        tmp = std::filesystem::temp_directory_path() / "qb-curl-h3-probe.txt";
    const std::string cmd = curl_cmd + " --version > \"" + tmp.string() + "\" 2>&1";
    std::system(cmd.c_str()); // rc is unreliable across shells; inspect the output instead
    std::string content;
    {
        std::ifstream in(tmp);
        content.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
    return content.find("HTTP3") != std::string::npos;
}

// Locates an HTTP/3-capable curl, in priority order: the QB_HTTP3_CURL override,
// the well-known Homebrew locations (macOS), then any curl on PATH — each
// verified to actually support HTTP/3. Returns {} when none is available (the
// interop test then skips cleanly).
std::filesystem::path
http3_curl_path() {
    if (auto const *configured = std::getenv("QB_HTTP3_CURL"); configured && *configured) {
        return configured;
    }
    for (auto const &candidate :
         {std::filesystem::path{"/opt/homebrew/opt/curl/bin/curl"}, std::filesystem::path{"/usr/local/opt/curl/bin/curl"}}) {
        if (std::filesystem::exists(candidate) && curl_command_has_http3("\"" + candidate.string() + "\"")) {
            return candidate;
        }
    }
#if defined(_WIN32)
    const std::filesystem::path on_path{"curl.exe"};
#else
    const std::filesystem::path on_path{"curl"};
#endif
    if (curl_command_has_http3(on_path.string())) {
        return on_path;
    }
    return {};
}

std::filesystem::path
configured_tool_path(char const *env_name) {
    if (auto const *configured = std::getenv(env_name); configured && *configured) {
        return configured;
    }
    return {};
}

std::string
configured_env_value(char const *env_name) {
    if (auto const *configured = std::getenv(env_name); configured && *configured) {
        return configured;
    }
    return {};
}

std::string
read_file(std::filesystem::path const &path) {
    std::ifstream in(path);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

struct CommandResult {
    int  exit_code = -1;
    bool timed_out = false;
};

// Forks the external command and, while waiting for it, keeps the qb event loop
// pumping so the in-process server can answer it. On timeout the child is
// SIGTERM'd then SIGKILL'd, and timed_out is reported.
CommandResult
run_command_while_pumping(std::string const &command, std::chrono::milliseconds timeout) {
#ifdef _WIN32
    (void) timeout;
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
    int        status   = 0;
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
    (void) waitpid(pid, &status, 0);
    return {-1, true};
#endif
}

} // namespace

TEST(Http3InteropTest, HomebrewCurlCanCallQbHttp3ServerWhenAvailable) {
    ASSERT_TRUE(certs_available()) << "HTTP/3 interop server probe requires the test TLS certificate pair";
    const auto curl = http3_curl_path();
    if (curl.empty()) {
        GTEST_SKIP() << "No HTTP/3-capable curl found (set QB_HTTP3_CURL, or install a curl built with HTTP/3)";
    }

    qb::io::async::init();

    const auto port   = ephemeral_udp_port();
    auto       server = qb::http3::make_server();
    server->router().get("/interop", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("content-type", "text/plain");
        ctx->response().body() = "curl-h3-ok";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    const auto base      = std::filesystem::temp_directory_path()
                           / ("qb-http3-curl-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    const auto body_path = base.string() + ".body";
    const auto code_path = base.string() + ".code";
    const auto err_path  = base.string() + ".err";

    const auto command = "\"" + curl.string()
                         + "\""
                           " --http3-only --insecure --silent --show-error --max-time 5"
                           " --output \""
                         + body_path
                         + "\""
                           " --write-out \"%{http_code}\""
                           " "
                         + https_origin(port) + "/interop" + " > \"" + code_path
                         + "\""
                           " 2> \""
                         + err_path + "\"";

    const auto result = run_command_while_pumping(command, 6s);

    const auto body = read_file(body_path);
    const auto code = read_file(code_path);
    const auto err  = read_file(err_path);

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
    ASSERT_TRUE(certs_available()) << "HTTP/3 interop server probe requires the test TLS certificate pair";
    const auto client_tool = configured_tool_path("QB_HTTP3_NGHTTP3_CLIENT");
    if (client_tool.empty() || !std::filesystem::exists(client_tool)) {
        GTEST_SKIP() << "Set QB_HTTP3_NGHTTP3_CLIENT to enable nghttp3-client interop";
    }

    qb::io::async::init();

    const auto port   = ephemeral_udp_port();
    auto       server = qb::http3::make_server();
    server->router().get("/nghttp3", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("content-type", "text/plain");
        ctx->response().body() = "nghttp3-client-ok";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    const auto base     = std::filesystem::temp_directory_path()
                          / ("qb-http3-nghttp3-client-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    const auto out_path = base.string() + ".out";
    const auto err_path = base.string() + ".err";

    const auto command = "\"" + client_tool.string() + "\" " + https_origin(port) + "/nghttp3" + " > \"" + out_path
                         + "\""
                           " 2> \""
                         + err_path + "\"";

    const auto result = run_command_while_pumping(command, 6s);

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
    ASSERT_TRUE(certs_available()) << "HTTP/3 interop server probe requires the test TLS certificate pair";
    const auto h3spec_tool = configured_tool_path("QB_HTTP3_H3SPEC");
    if (h3spec_tool.empty() || !std::filesystem::exists(h3spec_tool)) {
        GTEST_SKIP() << "Set QB_HTTP3_H3SPEC to enable h3spec interop";
    }

    qb::io::async::init();

    const auto port   = ephemeral_udp_port();
    auto       server = qb::http3::make_server();
    server->router().get("/", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "h3spec-ok";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    const auto base     = std::filesystem::temp_directory_path()
                          / ("qb-http3-h3spec-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    const auto out_path = base.string() + ".out";
    const auto err_path = base.string() + ".err";

    const auto command = "\"" + h3spec_tool.string() + "\" -host 127.0.0.1 -port " + std::to_string(port)
                         + " -insecure"
                           " > \""
                         + out_path
                         + "\""
                           " 2> \""
                         + err_path + "\"";

    const auto result = run_command_while_pumping(command, 20s);

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
    client->set_connect_timeout(5s);
    client->set_request_timeout(5s);
    if (configured_env_value("QB_HTTP3_EXTERNAL_INSECURE") == "1") {
        client->set_verify_peer(false);
    }

    auto response = qb::http::run_sync(client->push_request(qb::http::Request{std::move(target)}));

    const auto expected_status = configured_env_value("QB_HTTP3_EXTERNAL_EXPECT_STATUS");
    if (!expected_status.empty()) {
        EXPECT_EQ(response.status().code(), qb::to_number<int>(expected_status).value());
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

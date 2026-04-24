#include <gtest/gtest.h>
#include "../http.h"
#include <chrono>
#include <exception>
#include <filesystem>
#include <thread>

using namespace qb::io;

namespace {
    std::filesystem::path find_ssl_test_resource(const char *file_name) {
        const auto repo_root = std::filesystem::path(__FILE__).parent_path().parent_path().parent_path().parent_path();
        const std::filesystem::path candidates[] = {
            repo_root / "qb" / "resources" / "ssl" / file_name,
            repo_root / "out" / "build" / "x64-Release" / "bin" / "tests" / "ssl" / file_name,
            std::filesystem::current_path() / file_name,
            std::filesystem::current_path() / "ssl" / file_name,
            std::filesystem::current_path().parent_path() / "bin" / "tests" / "ssl" / file_name
        };

        for (const auto &candidate: candidates) {
            std::error_code ec;
            if (std::filesystem::exists(candidate, ec) && !ec) {
                return candidate;
            }
        }
        return candidates[0];
    }

    std::filesystem::path ssl_test_resource(const char *file_name) {
        return find_ssl_test_resource(file_name);
    }
}

constexpr const std::size_t NB_ITERATION = 4096;
constexpr const char STRING_MESSAGE[] = "Here is my content test";
std::atomic<std::size_t> msg_count_server_side = 0;
std::atomic<std::size_t> msg_count_client_side = 0;

bool
all_done() {
    return msg_count_server_side == (NB_ITERATION) &&
           msg_count_client_side == NB_ITERATION;
}

namespace {
    /// Pumps the current thread's @c async loop until @p done(), or the wall @p time_budget,
    /// whichever comes first. @return true if @p done() became true; false on timeout.
    /// Used for two-threaded SSL/TCP session tests: the main and worker threads must both
    /// keep dispatching the reactor until the test completes; a fixed EVRUN_ONCE count can
    /// end early on the server thread, then thread join blocks while the client still needs
    /// the server to run on the main event loop.
    template <typename F>
    bool
    pump_event_loop_while(const F &done, const std::chrono::steady_clock::duration time_budget) {
        const auto deadline = std::chrono::steady_clock::now() + time_budget;
        for (;;) {
            if (done()) {
                return true;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                return false;
            }
            async::run(EVRUN_ONCE);
        }
    }
} // namespace

TEST(Session, HTTP_PARSE_CONTENT_TYPE) {
    // std::string
    auto res = qb::http::Request::ContentType("application/json;charset=utf-16");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-16");
    res = qb::http::Request::ContentType(
        "   application/json   ;   charset    =   utf-16   ");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-16");
    res = qb::http::Request::ContentType("application/json;charset=\"utf-16\"");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-16");
    res = qb::http::Request::ContentType("application/json;charset=utf-16;");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-16");
    res = qb::http::Request::ContentType("application/json;charset=");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-8");
    res = qb::http::Request::ContentType("application/json;charlot=utf-16");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-8");
    res = qb::http::Request::ContentType("application/json;");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-8");
    res = qb::http::Request::ContentType("");
    EXPECT_EQ(res.type(), "application/octet-stream");
    EXPECT_EQ(res.charset(), "utf-8");
    // std::string_view
    auto res2 = qb::http::Request::ContentType("application/json;charset=utf-16");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf-16");
    res2 = qb::http::Request::ContentType(
        "   application/json   ;   charset    =   utf-16   ");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf-16");
    res2 = qb::http::Request::ContentType("application/json;charset=\"utf-16\"");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf-16");
    res2 = qb::http::Request::ContentType("application/json;charset=utf-16;");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf-16");
    res2 = qb::http::Request::ContentType("application/json;charset=");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf-8");
    res2 = qb::http::Request::ContentType("application/json;charlot=utf-16");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf-8");
    res2 = qb::http::Request::ContentType("application/json;");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf-8");
    res2 = qb::http::Request::ContentType("");
    EXPECT_EQ(res2.type(), "application/octet-stream");
    EXPECT_EQ(res2.charset(), "utf-8");
}

TEST(Session, HTTP_PARSE_MULTIPART) {
    qb::http::Multipart mp;

    auto &part1 = mp.create_part();
    part1.headers()["Content-Disposition"] = {R"(form-data; name="company")"};
    part1.headers()["Content-Type"] = {"text"};
    part1.body = "isndev";
    auto &part2 = mp.create_part();
    part2.headers()["Content-Disposition"] = {
        R"(file; name="file"; filename="file1.txt")"
    };
    part2.headers()["Content-Type"] = {"application/json"};
    part2.body = R"({"hello": "true"})";

    qb::icase_unordered_map<std::string> op{{"Content-Type", {"multipart/form-data"}}};
    qb::http::Request req{
        HTTP_POST,
        {"https://isndev.com"},
        {{"Content-Type", {"multipart/form-data"}}},
        mp
    };
    req.body() = mp;

    auto mp2 = req.body().as<qb::http::Multipart>();
    EXPECT_EQ(mp2.parts()[0].header("Content-Type"), "text");
    EXPECT_EQ(mp2.parts()[0].body, "isndev");
    auto attrs =
            qb::http::parse_header_attributes(mp2.parts()[0].header("Content-Disposition"));
    EXPECT_TRUE(attrs.has("Form-Data"));
    EXPECT_EQ(attrs.at("name"), "company");

    EXPECT_EQ(mp2.parts()[1].header("Content-Type"), "application/json");
    EXPECT_EQ(mp2.parts()[1].body, R"({"hello": "true"})");
    attrs =
            qb::http::parse_header_attributes(mp2.parts()[1].header("Content-Disposition"));
    EXPECT_TRUE(attrs.has("File"));
    EXPECT_EQ(attrs.at("Name"), "file");
    EXPECT_EQ(attrs.at("Filename"), "file1.txt");
}

class HostHeaderCaptureServer;

class HostHeaderCaptureClient : public qb::io::use<HostHeaderCaptureClient>::tcp::client<HostHeaderCaptureServer> {
public:
    constexpr static const bool has_server = true;
    using Protocol = qb::http::protocol<HostHeaderCaptureClient>;

    explicit HostHeaderCaptureClient(HostHeaderCaptureServer &server)
        : client(server) {
    }

    static std::string captured_host_header;

    void on(Protocol::request &&request) {
        captured_host_header = request.header("host");
        qb::http::Response r;
        r.status() = qb::http::status::OK;
        r.body() = "ok";
        *this << r;
    }
};

class HostHeaderCaptureServer : public qb::http::use<HostHeaderCaptureServer>::server<HostHeaderCaptureClient> {
};

std::string HostHeaderCaptureClient::captured_host_header;

TEST(Session, HTTP_CLIENT_SETS_HOST_HEADER_WITH_NON_DEFAULT_PORT) {
    async::init();
    HostHeaderCaptureClient::captured_host_header.clear();

    HostHeaderCaptureServer server;
    server.transport().listen_v4(9987);
    server.start();

    qb::http::Request req{{"http://localhost:9987/host-check"}};
    auto reply = qb::http::run_sync(qb::http::GET(req, 3.0));

    EXPECT_EQ(reply.response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(HostHeaderCaptureClient::captured_host_header, "localhost:9987");
}

TEST(Session, HTTP_HOST_HEADER_FORMATS_IPV6_WITH_BRACKETS) {
    qb::io::uri uri{"http://[2001:db8::1]/resource"};
    EXPECT_EQ(qb::http::host_header_value(uri), "[2001:db8::1]");
}

TEST(Session, HTTP_HOST_HEADER_FORMATS_IPV6_WITH_PORT_AND_BRACKETS) {
    qb::io::uri uri{"http://[2001:db8::1]:8080/resource"};
    EXPECT_EQ(qb::http::host_header_value(uri), "[2001:db8::1]:8080");
}

TEST(Session, HTTP_HOST_VALUE_OMITS_EXPLICIT_DEFAULT_HTTP_PORT) {
    const qb::io::uri u{"http://api.example.com:80/v1"};
    EXPECT_EQ(u.port(), "80");
    EXPECT_EQ(qb::http::host_header_value(u), "api.example.com");
}

TEST(Session, HTTP_HOST_VALUE_OMITS_EXPLICIT_DEFAULT_HTTPS_PORT) {
    const qb::io::uri u{"https://api.example.com:443/secure"};
    EXPECT_EQ(u.port(), "443");
    EXPECT_EQ(qb::http::host_header_value(u), "api.example.com");
}

TEST(Session, HTTP_HOST_VALUE_OMITS_HTTPS_DEFAULT_PORT_ON_IPV6) {
    const qb::io::uri u{"https://[2001:db8::1]:443/secure"};
    EXPECT_EQ(qb::http::host_header_value(u), "[2001:db8::1]");
}

TEST(Session, HTTP_HOST_VALUE_RETAINS_NON_DEFAULT_PORT) {
    const qb::io::uri u{"https://api.example.com:4443/secure"};
    EXPECT_EQ(qb::http::host_header_value(u), "api.example.com:4443");
}

TEST(Session, HTTP_HOST_VALUE_DEFAULT_PORTS_SCHEMES_CASE_INSENSITIVE) {
    // Mixed-case schemes must still elide :80 / :443; value matches uri.host() (any casing the parser uses).
    const qb::io::uri a{"HTTP://host-ssl-test.example:80/p"};
    const qb::io::uri b{"HtTpS://host-ssl-test2.example:443/p"};
    EXPECT_EQ(a.port(), "80");
    EXPECT_EQ(b.port(), "443");
    EXPECT_EQ(qb::http::host_header_value(a), std::string(a.host()));
    EXPECT_EQ(qb::http::host_header_value(b), std::string(b.host()));
}

// OVER TCP

class TestServer;

class TestServerClient : public qb::io::use<TestServerClient>::tcp::client<TestServer> {
public:
    constexpr static const bool has_server = true;

    using Protocol = qb::http::protocol<TestServerClient>;

    explicit TestServerClient(TestServer &server)
        : client(server) {
    }

    ~TestServerClient() {
    }

    void
    on(Protocol::request &&request) {
        EXPECT_EQ(request.method(), HTTP_GET);
        EXPECT_NE(request.headers().size(), 0u);
        EXPECT_EQ(request.header("connection"), "keep-alive");
        EXPECT_EQ(request.query("happy"), "true");
        EXPECT_EQ(request.body().size(), sizeof(STRING_MESSAGE) - 1);

        qb::http::Response r;
        r.status() = qb::http::status::OK;
        r.body() = std::move(request.body());
        *this << r;

        ++msg_count_server_side;
    }
};

class TestServer : public qb::http::use<TestServer>::server<TestServerClient> {
    std::size_t connection_count = 0u;

public:
    ~TestServer() {
        EXPECT_EQ(msg_count_server_side, NB_ITERATION);
        EXPECT_TRUE(connection_count >= 1u);
    }

    void
    on(IOSession &s) {
        ++connection_count;
    }
};

class TestClient : public use<TestClient>::tcp::client<> {
public:
    using Protocol = qb::http::protocol<TestClient>;

    ~TestClient() {
        EXPECT_EQ(msg_count_client_side, NB_ITERATION);
    }

    void
    on(Protocol::response &&response) {
        EXPECT_EQ(response.status(), HTTP_STATUS_OK);
        ++msg_count_client_side;
    }
};

TEST(Session, HTTP_OVER_TCP) {
    async::init();

    auto res = qb::http::run_sync(qb::http::GET(qb::http::Request{{"https://isndev.com"}})).response;

    msg_count_server_side = 0;
    msg_count_client_side = 0;

    TestServer server;
    server.transport().listen_v4(9999);
    server.start();

    std::thread t([]() {
        async::init();
        TestClient client;
        if (SocketStatus::Done != client.transport().connect_v4("127.0.0.1", 9999)) {
            throw std::runtime_error("could not connect");
        }
        client.start();

        qb::http::Request r{
            HTTP_GET,
            {"http://www.isndev.test:9999/?happy=true"},
            {
                {"Host", {"www.isndev.test:9999"}},
                {"Connection", {"keep-alive"}},
                {"Transfer-Encoding", {"chunked"}}
            }
        };

        for (auto i = 0u; i < NB_ITERATION; ++i) {
            client << r;
            client << qb::http::Chunk(STRING_MESSAGE, sizeof(STRING_MESSAGE) - 1)
                    << qb::http::Chunk();
        }

        for (auto i = 0; i < (NB_ITERATION * 5) && !all_done(); ++i)
            async::run(EVRUN_ONCE);
    });

    for (auto i = 0; i < (NB_ITERATION * 5) && !all_done(); ++i)
        async::run(EVRUN_ONCE);
    t.join();
}

TEST(Session, HTTP_OVER_TCP_ASYNC_GET) {
    async::init();
    msg_count_server_side = 0;
    msg_count_client_side = 0;

    TestServer server;
    server.transport().listen_v4(9999);
    server.start();

    std::thread t([]() {
        async::init();

        qb::http::Request r{
            {"http://localhost:9999/?happy=true"},
            {
                {"Host", {"www.isndev.test:9999"}},
                {"Connection", {"keep-alive"}},
                {"Authorization", {"None"}}
            },
            {STRING_MESSAGE}
        };

        for (auto i = 0u; i < NB_ITERATION; ++i) {
            auto res = qb::http::run_sync(qb::http::GET(r)).response;
            EXPECT_EQ(res.status(), HTTP_STATUS_OK);
            ++msg_count_client_side;
        }
    });

    while (!all_done())
        async::run(EVRUN_ONCE);
    t.join();
}

// OVER SECURE TCP

#ifdef QB_HAS_SSL

class TestSecureServer;

class TestSecureServerClient
        : public use<TestSecureServerClient>::tcp::ssl::client<TestSecureServer> {
public:
    using Protocol = qb::http::protocol<TestSecureServerClient>;

    explicit TestSecureServerClient(IOServer &server)
        : client(server) {
    }

    ~TestSecureServerClient() = default;

    void
    on(Protocol::request &&request) {
        EXPECT_EQ(request.method(), HTTP_GET);
        EXPECT_EQ(request.headers().size(), 3u);
        EXPECT_EQ(request.header("connection"), "keep-alive");
        EXPECT_EQ(request.query("happy"), "true");
        EXPECT_EQ(request.body().size(), sizeof(STRING_MESSAGE) - 1);

        qb::http::Response r;
        r.status() = qb::http::status::OK;
        r.body() = std::move(request.body());
        *this << r;

        ++msg_count_server_side;
    }
};

class TestSecureServer
        : public use<TestSecureServer>::tcp::ssl::server<TestSecureServerClient> {
    std::size_t connection_count = 0u;

public:
    void
    on(IOSession &) {
        ++connection_count;
    }

    [[nodiscard]] std::size_t connectionCount() const noexcept {
        return connection_count;
    }
};

class TestSecureClient : public use<TestSecureClient>::tcp::ssl::client<> {
public:
    using Protocol = qb::http::protocol<TestSecureClient>;

    void
    on(Protocol::response &&response) {
        EXPECT_EQ(response.status(), HTTP_STATUS_OK);
        ++msg_count_client_side;
    }
};

TEST(Session, HTTP_OVER_SECURE_TCP) {
    async::init();

    const auto cert_path = ssl_test_resource("cert.pem");
    const auto key_path = ssl_test_resource("key.pem");
    ASSERT_TRUE(std::filesystem::exists(cert_path)) << "Missing SSL certificate: " << cert_path;
    ASSERT_TRUE(std::filesystem::exists(key_path)) << "Missing SSL key: " << key_path;

    msg_count_server_side = 0;
    msg_count_client_side = 0;
    // Wall-clock budget: TLS is slower than plain TCP, and the main thread (server) must
    // keep running until all work completes; a limited EVRUN_ONCE count on one thread can
    // return before t.join (deadlock on Windows with asymmetric scheduling).
    const auto kSslSessionBudget = std::chrono::minutes(3);
    TestSecureServer server;
    server.transport().init(
        ssl::create_server_context(
            SSLv23_server_method(),
            cert_path.string(),
            key_path.string()));
    ASSERT_EQ(server.transport().listen_v6(9999), 0);
    server.start();

    std::exception_ptr worker_error;
    std::thread t([&worker_error, kSslSessionBudget]() {
        try {
            async::init();
            TestSecureClient client;
            if (SocketStatus::Done !=
                client.transport().connect(uri{"tcp://[::1]:9999", AF_INET6})) {
                throw std::runtime_error("could not connect");
            }
            client.start();

            qb::http::Request r{
                HTTP_GET,
                {"http://www.isndev.test:9999/?happy=true"},
                {{"Host", {"www.isndev.test:9999"}}, {"Connection", {"keep-alive"}}},
                {STRING_MESSAGE}
            };

            for (auto i = 0u; i < NB_ITERATION; ++i) {
                client << r;
            }

            (void) pump_event_loop_while(
                [] {
                    return all_done();
                },
                kSslSessionBudget);
        } catch (...) {
            worker_error = std::current_exception();
        }
    });

    (void) pump_event_loop_while(
        [&worker_error] {
            if (worker_error != std::exception_ptr()) {
                return true;
            }
            return all_done();
        },
        kSslSessionBudget);

    t.join();

    if (worker_error) {
        std::rethrow_exception(worker_error);
    }

    EXPECT_EQ(msg_count_server_side.load(), NB_ITERATION);
    EXPECT_EQ(msg_count_client_side.load(), NB_ITERATION);
    EXPECT_EQ(server.connectionCount(), 1u);
}

#endif

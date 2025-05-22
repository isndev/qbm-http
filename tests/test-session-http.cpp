#include <gtest/gtest.h>
#include "../http.h"

using namespace qb::io;

constexpr const std::size_t NB_ITERATION = 4096;
constexpr const char STRING_MESSAGE[] = "Here is my content test";
std::atomic<std::size_t> msg_count_server_side = 0;
std::atomic<std::size_t> msg_count_client_side = 0;

bool
all_done() {
    return msg_count_server_side == (NB_ITERATION) &&
           msg_count_client_side == NB_ITERATION;
}

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
    auto res2 = qb::http::RequestView::ContentType("application/json;charset=utf-16");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf-16");
    res2 = qb::http::RequestView::ContentType(
        "   application/json   ;   charset    =   utf-16   ");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf-16");
    res2 = qb::http::RequestView::ContentType("application/json;charset=\"utf-16\"");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf-16");
    res2 = qb::http::RequestView::ContentType("application/json;charset=utf-16;");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf-16");
    res2 = qb::http::RequestView::ContentType("application/json;charset=");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf-8");
    res2 = qb::http::RequestView::ContentType("application/json;charlot=utf-16");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf-8");
    res2 = qb::http::RequestView::ContentType("application/json;");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf-8");
    res2 = qb::http::RequestView::ContentType("");
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
    on(Protocol::request &&event) {
        EXPECT_EQ(event.http.method(), HTTP_GET);
        EXPECT_NE(event.http.headers().size(), 0u);
        EXPECT_EQ(event.http.header("connection"), "keep-alive");
        EXPECT_EQ(event.http.query("happy"), "true");
        EXPECT_EQ(event.http.body().size(), sizeof(STRING_MESSAGE) - 1);

        qb::http::Response r;
        r.status() = qb::http::status::OK;
        r.body() = std::move(event.http.body());
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
    on(Protocol::response &&event) {
        EXPECT_EQ(event.http.status(), HTTP_STATUS_OK);
        ++msg_count_client_side;
    }
};

TEST(Session, HTTP_OVER_TCP) {
    async::init();

    auto res = qb::http::GET(qb::http::Request{{"https://isndev.com"}});

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
            auto res = qb::http::GET(r);
            EXPECT_EQ(res.status(), HTTP_STATUS_OK);
            ++msg_count_client_side;
        }
    });

    while (!all_done())
        async::run(EVRUN_ONCE);
    t.join();
}

// OVER SECURE TCP

#ifdef QB_IO_WITH_SSL

class TestSecureServer;

class TestSecureServerClient
        : public use<TestSecureServerClient>::tcp::ssl::client<TestSecureServer> {
public:
    using Protocol = qb::http::protocol_view<TestSecureServerClient>;

    explicit TestSecureServerClient(IOServer &server)
        : client(server) {
    }

    ~TestSecureServerClient() {
        EXPECT_EQ(msg_count_server_side, NB_ITERATION);
    }

    void
    on(Protocol::request &&event) {
        EXPECT_EQ(event.http.method(), HTTP_GET);
        EXPECT_EQ(event.http.headers().size(), 3u);
        EXPECT_EQ(event.http.header("connection"), "keep-alive");
        EXPECT_EQ(event.http.query("happy"), "true");
        EXPECT_EQ(event.http.body().size(), sizeof(STRING_MESSAGE) - 1);

        qb::http::Response r;
        r.status() = qb::http::status::OK;
        r.body() = std::move(event.http.body());
        *this << r;

        ++msg_count_server_side;
    }
};

class TestSecureServer
        : public use<TestSecureServer>::tcp::ssl::server<TestSecureServerClient> {
    std::size_t connection_count = 0u;

public:
    ~TestSecureServer() {
        EXPECT_EQ(connection_count, 1u);
    }

    void
    on(IOSession &) {
        ++connection_count;
    }
};

class TestSecureClient : public use<TestSecureClient>::tcp::ssl::client<> {
public:
    using Protocol = qb::http::protocol_view<TestSecureClient>;

    ~TestSecureClient() {
        EXPECT_EQ(msg_count_client_side, NB_ITERATION);
    }

    void
    on(Protocol::response &&event) {
        EXPECT_EQ(event.http.status(), HTTP_STATUS_OK);
        ++msg_count_client_side;
    }
};

TEST(Session, HTTP_OVER_SECURE_TCP) {
    async::init();
    msg_count_server_side = 0;
    msg_count_client_side = 0;

    TestSecureServer server;
    server.transport().init(
        ssl::create_server_context(SSLv23_server_method(), "cert.pem", "key.pem"));
    server.transport().listen_v6(9999);
    server.start();

    std::thread t([]() {
        async::init();
        TestSecureClient client;
        if (SocketStatus::Done !=
            client.transport().connect(uri{"tcp://localhost:9999", AF_INET6})) {
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

        for (auto i = 0; i < (NB_ITERATION * 5) && !all_done(); ++i)
            async::run(EVRUN_ONCE);
    });

    for (auto i = 0; i < (NB_ITERATION * 5) && !all_done(); ++i)
        async::run(EVRUN_ONCE);
    t.join();
}

#endif

// #include <gtest/gtest.h>
// #include "../http.h"
//
// class HttpServer;
// class HttpSession : public qb::http::use<HttpSession>::session<HttpServer>
// {
// public:
//     HttpSession(HttpServer &server)
//         : session(server) {}
// };
//
// class HttpServer : public qb::http::use<HttpServer>::server<HttpSession> {
// public:
//
//     HttpServer() {
//         router().get("/", [](auto ctx) {
//             ctx->response().status() = qb::http::status::OK;
//             ctx->response().body()      = "Hello, World!";
//             ctx->complete();
//         });
//     }
// };
//
// TEST(Session, HTTP_SIMPLE_SERVER) {
//     HttpServer server;
//     server.transport().listen_v4(9999);
//     server.start();
//
//     while (true) {
//         async::run(EVRUN_ONCE);
//     }
// }

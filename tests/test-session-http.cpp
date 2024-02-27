/*
 * qb - C++ Actor Framework
 * Copyright (C) 2011-2021 isndev (www.qbaf.io). All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *         limitations under the License.
 */

#include "../http.h"
#include <atomic>
#include <gtest/gtest.h>
#include <qb/io/async.h>
#include <thread>

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
    auto res = qb::http::Request::ContentType("application/json;charset=utf16");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf16");
    res = qb::http::Request::ContentType("   application/json   ;   charset    =   utf16   ");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf16");
    res = qb::http::Request::ContentType("application/json;charset=\"utf16\"");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf16");
    res = qb::http::Request::ContentType("application/json;charset=utf16;");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf16");
    res = qb::http::Request::ContentType("application/json;charset=");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf8");
    res = qb::http::Request::ContentType("application/json;charlot=utf16");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf8");
    res = qb::http::Request::ContentType("application/json;");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf8");
    res = qb::http::Request::ContentType("");
    EXPECT_EQ(res.type(), "application/octet-stream");
    EXPECT_EQ(res.charset(), "utf8");
    // std::string_view
    auto res2 = qb::http::RequestView::ContentType("application/json;charset=utf16");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf16");
    res2 = qb::http::RequestView::ContentType("   application/json   ;   charset    =   utf16   ");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf16");
    res2 = qb::http::RequestView::ContentType("application/json;charset=\"utf16\"");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf16");
    res2 = qb::http::RequestView::ContentType("application/json;charset=utf16;");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf16");
    res2 = qb::http::RequestView::ContentType("application/json;charset=");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf8");
    res2 = qb::http::RequestView::ContentType("application/json;charlot=utf16");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf8");
    res2 = qb::http::RequestView::ContentType("application/json;");
    EXPECT_EQ(res2.type(), "application/json");
    EXPECT_EQ(res2.charset(), "utf8");
    res2 = qb::http::RequestView::ContentType("");
    EXPECT_EQ(res2.type(), "application/octet-stream");
    EXPECT_EQ(res2.charset(), "utf8");
}

TEST(Session, HTTP_PARSE_MULTIPART) {
    qb::http::Multipart mp;

    auto &part1 = mp.create_part();
    part1.headers()["Content-Disposition"] = {R"(form-data; name="company")"};
    part1.headers()["Content-Type"] = {"text"};
    part1.body = "isndev";
    auto &part2 = mp.create_part();
    part2.headers()["Content-Disposition"] = {R"(file; name="file"; filename="file1.txt")"};
    part2.headers()["Content-Type"] = {"application/json"};
    part2.body = R"({"hello": "true"})";

    qb::icase_unordered_map<std::string> op{{"Content-Type", {"multipart/form-data"}}};
    qb::http::Request req{HTTP_POST, {"https://isndev.com"}, {{"Content-Type", {"multipart/form-data"}}}, mp};
    req.body() = mp;

    auto mp2 = req.body().as<qb::http::Multipart>();
    EXPECT_EQ(mp2.parts()[0].header("Content-Type"), "text");
    EXPECT_EQ(mp2.parts()[0].body, "isndev");
    auto attrs = qb::http::parse_header_attributes(mp2.parts()[0].header("Content-Disposition"));
    EXPECT_TRUE(attrs.has("Form-Data"));
    EXPECT_EQ(attrs.at("name"), "company");

    EXPECT_EQ(mp2.parts()[1].header("Content-Type"), "application/json");
    EXPECT_EQ(mp2.parts()[1].body, R"({"hello": "true"})");
    attrs = qb::http::parse_header_attributes(mp2.parts()[1].header("Content-Disposition"));
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
        : client(server) {}

    ~TestServerClient() {}

    void
    on(Protocol::request &&event) {
        EXPECT_EQ(event.http.method, HTTP_GET);
        EXPECT_NE(event.http.headers().size(), 0u);
        EXPECT_EQ(event.http.header("connection"), "keep-alive");
        EXPECT_EQ(event.http.query("happy"), "true");
        EXPECT_EQ(event.http.body().size(), sizeof(STRING_MESSAGE) - 1);

        qb::http::Response r;
        r.status_code = HTTP_STATUS_OK;
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
        EXPECT_EQ(event.http.status_code, HTTP_STATUS_OK);
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
            {{"Host", {"www.isndev.test:9999"}}, {"Connection", {"keep-alive"}}, {"Transfer-Encoding", {"chunked"}}}};

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
            {{"Host", {"www.isndev.test:9999"}}, {"Connection", {"keep-alive"}}, {"Authorization", {"None"}}},
            {STRING_MESSAGE}};

        for (auto i = 0u; i < NB_ITERATION; ++i) {
            auto res = qb::http::GET(r);
            EXPECT_EQ(res.status_code, HTTP_STATUS_OK);
            ++msg_count_client_side;
        }
    });

    for (auto i = 0; !all_done(); ++i)
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
        : client(server) {}

    ~TestSecureServerClient() {
        EXPECT_EQ(msg_count_server_side, NB_ITERATION);
    }

    void
    on(Protocol::request &&event) {
        EXPECT_EQ(event.http.method, HTTP_GET);
        EXPECT_EQ(event.http.headers().size(), 3u);
        EXPECT_EQ(event.http.header("connection"), "keep-alive");
        EXPECT_EQ(event.http.query("happy"), "true");
        EXPECT_EQ(event.http.body().size(), sizeof(STRING_MESSAGE) - 1);

        qb::http::Response r;
        r.status_code = HTTP_STATUS_OK;
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
        EXPECT_EQ(event.http.status_code, HTTP_STATUS_OK);
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
        if (SocketStatus::Done != client.transport().connect(uri{"tcp://localhost:9999", AF_INET6})) {
            throw std::runtime_error("could not connect");
        }
        client.start();

        qb::http::Request r{
            HTTP_GET,
            {"http://www.isndev.test:9999/?happy=true"},
            {{"Host", {"www.isndev.test:9999"}}, {"Connection", {"keep-alive"}}},
            {STRING_MESSAGE}};

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


class HttpServer;
class HttpSession : public qb::http::use<HttpSession>::session<HttpServer> {
public:
    explicit HttpSession(HttpServer &server)
        : session(server) {
        setTimeout(0);
    }
    ~HttpSession() {
        // disconnected here
    }
    // use middleware here
    void on(qb::http::event::request &&) {
        response().headers()["date"] = {qb::http::date::to_string(qb::NanoTimestamp{})};
    }
};

class HttpServer : public qb::http::use<HttpServer>::server<HttpSession> {
    class Posts : public Router::Controller {
        class GetAllPosts : public Route {
        public:
            GetAllPosts()
                : Route("/?", [](auto &ctx) {
                    msg_count_server_side++;
                    ctx.response.body() = "all posts with offset=" + ctx.request.query("offset");
                    ctx.session << ctx.response;
                }){};
        };
        class GetPostById : public Route {
        public:
            GetPostById()
                : Route("/:id", [](auto &ctx) {
                    msg_count_server_side++;
                    ctx.response.body() = "one post id=" + ctx.param("id");
                    ctx.session << ctx.response;
                }){};
        };
    public:
        Posts() : Controller("/posts") {
            router()
                .GET<GetAllPosts>()
                .GET<GetPostById>();
        }
    };
public:
    HttpServer()  {
        qb::http::Response initial;
        initial.status_code = HTTP_STATUS_OK;
        initial.headers()["server"] = {"qb/2.0"};

        router().set_default_response(std::move(initial));
        router()
            // classic just with lambda
            .GET(
                "/",
                [](auto &ctx) {
                    auto msg = ctx.request.body().template as<std::string>();
                    EXPECT_EQ(msg, STRING_MESSAGE);
                    EXPECT_TRUE(ctx.response.headers().has("Date"));
                    ctx.response.body() = std::move(ctx.request.body());
                    ctx.session << ctx.response;
                    ++msg_count_server_side;
                })
            // add controller
            .controller<Posts>();

    }
    ~HttpServer() = default;
};


TEST(HTTP_SERVER, TCP_ADVANCED_ROUTING) {
    async::init();
    msg_count_server_side = 0;
    HttpServer server;
    bool status = true;

    server.transport().listen(qb::io::uri{"tcp://0.0.0.0:9999"});
    server.start();

    std::thread t([&]() {
        async::init();
        qb::http::Request request;

        request.uri() = "http://localhost:9999";
        request.body() = STRING_MESSAGE;
        auto response = qb::http::GET(request);
        EXPECT_EQ(response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(response.body().as<std::string>(), STRING_MESSAGE);

        request.uri() = "http://localhost:9999/posts/?offset=10";
        response = qb::http::GET(request);
        EXPECT_EQ(response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(response.body().as<std::string>(), "all posts with offset=10");

        request.uri() = "http://localhost:9999/posts?offset=10";
        response = qb::http::GET(request);
        EXPECT_EQ(response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(response.body().as<std::string>(), "all posts with offset=10");


        request.uri() = "http://localhost:9999/posts/1000";
        response = qb::http::GET(request);
        EXPECT_EQ(response.status_code, HTTP_STATUS_OK);
        EXPECT_EQ(response.body().as<std::string>(), "one post id=1000");

        request.uri() = "http://localhost:9999/bad_route";
        response = qb::http::GET(request);
        EXPECT_EQ(response.status_code, HTTP_STATUS_NOT_FOUND);

        msg_count_client_side = 1;
        status = false;
    });

    while (status)
        async::run(EVRUN_ONCE);
    t.join();
}

#ifdef QB_IO_WITH_SSL

class HttpSecureServer;
class HttpSecureSession : public qb::http::use<HttpSecureSession>::ssl::session<HttpSecureServer> {
public:
    explicit HttpSecureSession(HttpSecureServer &server)
        : session(server) {}

    ~HttpSecureSession() {}
};

class HttpSecureServer : public qb::http::use<HttpSecureServer>::ssl::server<HttpSecureSession> {

public:
    HttpSecureServer()  {
        router().GET("/secure", [](auto &ctx){
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = STRING_MESSAGE;

            ctx.session << ctx.response;
            ++msg_count_server_side;
        });

    }
    ~HttpSecureServer() = default;
};

TEST(HTTP_SERVER, OVER_SECURE_TCP) {
    async::init();
    msg_count_server_side = 0;
    msg_count_client_side = 0;

    HttpSecureServer server;
    server.transport().init(
        ssl::create_server_context(SSLv23_server_method(), "cert.pem", "key.pem"));
    server.transport().listen_v4(9999);
    server.start();

    std::thread t([]() {
        async::init();
        for (auto i = 0u; i < NB_ITERATION; ++i) {
            qb::http::Request request;
            request.uri() = "https://localhost:9999/secure";
            request.body() = STRING_MESSAGE;
            auto response = qb::http::GET(request);
            EXPECT_EQ(response.body().as<std::string>(), STRING_MESSAGE);
            ++msg_count_client_side;
        }

        for (auto i = 0; i < (NB_ITERATION * 500) && !all_done(); ++i)
            async::run(EVRUN_ONCE);
    });

    for (auto i = 0; i < (NB_ITERATION * 500) && !all_done(); ++i)
        async::run(EVRUN_ONCE);
    t.join();
}

#endif

class HttpServerView;
class HttpSessionView : public qb::http::use<HttpSessionView>::session_view<HttpServerView> {
public:
    explicit HttpSessionView(HttpServerView &server)
        : session(server) {}

    ~HttpSessionView() {}
};

class HttpServerView : public qb::http::use<HttpServerView>::server<HttpSessionView> {

public:
    HttpServerView() {
        router().GET("/", [](auto &ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = STRING_MESSAGE;

            ctx.session << ctx.response;
            ++msg_count_server_side;
        });
    }
    ~HttpServerView() = default;
};

TEST(HTTP_SERVER_VIEW, OVER_TCP) {
    async::init();
    msg_count_server_side = 0;
    msg_count_client_side = 0;
    HttpServerView server;

    server.transport().listen(qb::io::uri{"tcp://0.0.0.0:9999"});
    server.start();

    std::thread t([]() {
        async::init();
        for (auto i = 0u; i < NB_ITERATION; ++i) {
            qb::http::Request request;
            request.uri() = "http://localhost:9999";
            request.body() = STRING_MESSAGE;
            auto response = qb::http::GET(request);
            EXPECT_EQ(response.body().as<std::string>(), STRING_MESSAGE);
            ++msg_count_client_side;
        }

        for (auto i = 0; i < (NB_ITERATION * 5) && !all_done(); ++i)
            async::run(EVRUN_ONCE);
    });

    for (auto i = 0; i < (NB_ITERATION * 5) && !all_done(); ++i)
        async::run(EVRUN_ONCE);
    t.join();
}


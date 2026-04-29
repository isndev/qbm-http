#include <atomic>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <gtest/gtest.h>
#include <stdexcept>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../http.h"

namespace {

class Http1ClientTestServer;

class Http1ClientTestSession
    : public qb::http::use<Http1ClientTestSession>::session<Http1ClientTestServer> {
public:
    explicit Http1ClientTestSession(Http1ClientTestServer& server);
};

class Http1ClientTestServer
    : public qb::http::use<Http1ClientTestServer>::server<Http1ClientTestSession> {
    std::atomic<int>& _connection_count;
    std::atomic<int>& _request_count;

public:
    Http1ClientTestServer(std::atomic<int>& connection_count,
                          std::atomic<int>& request_count)
        : _connection_count(connection_count)
        , _request_count(request_count) {
        router().get("/ping", [this](auto ctx) {
            ++_request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "pong";
            ctx->response().set_header("X-Protocol", "HTTP/1.1");
            ctx->complete();
        });

        router().get("/close", [this](auto ctx) {
            ++_request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "bye";
            ctx->response().set_header("Connection", "close");
            ctx->complete();
        });

        router().get("/item/:id", [this](auto ctx) {
            ++_request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = ctx->path_param("id");
            ctx->complete();
        });

        router().get("/hold/:id", [this](auto ctx) {
            ++_request_count;
            auto id = ctx->path_param("id");
            qb::io::async::callback([ctx, id = std::move(id)]() mutable {
                ctx->response().status() = qb::http::status::OK;
                ctx->response().body() = id;
                ctx->complete();
            }, 0.05);
        });

        router().get("/never", [this](auto ctx) {
            ++_request_count;
            (void)ctx;
        });

        router().post("/echo", [this](auto ctx) {
            ++_request_count;
            ctx->response().status() = qb::http::status::CREATED;
            ctx->response().body() = ctx->request().body().template as<std::string>();
            ctx->complete();
        });

        router().head("/head-length", [this](auto ctx) {
            ++_request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "123");
            ctx->response().set_header("X-Head", "ok");
            ctx->complete();
        });

        router().get("/no-content", [this](auto ctx) {
            ++_request_count;
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });

        router().compile();
    }

    void on(IOSession&) {
        ++_connection_count;
    }
};

Http1ClientTestSession::Http1ClientTestSession(Http1ClientTestServer& server)
    : session(server) {
    max_pipelined_requests(4);
}

struct RunningHttp1Server {
    explicit RunningHttp1Server(int port)
        : port(port) {
        qb::io::async::init();
        thread = std::thread([this] {
            qb::io::async::init();
            Http1ClientTestServer server(connection_count, request_count);
            server.transport().listen_v4(this->port);
            server.start();
            ready.store(true, std::memory_order_release);
            while (running.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(2));
                }
            }
        });
        while (!ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    ~RunningHttp1Server() {
        running.store(false, std::memory_order_release);
        if (thread.joinable()) {
            thread.join();
        }
    }

    [[nodiscard]] std::string url(std::string const& path) const {
        return "http://127.0.0.1:" + std::to_string(port) + path;
    }

    int port;
    std::thread thread;
    std::atomic<bool> ready{false};
    std::atomic<bool> running{true};
    std::atomic<int> connection_count{0};
    std::atomic<int> request_count{0};
};

qb::http::Request request(qb::http::method method, std::string const& target) {
    qb::http::Request req{method, qb::io::uri(target)};
    return req;
}

[[nodiscard]] std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

class raw_socket {
    int _fd = -1;

public:
    explicit raw_socket(int port) {
        _fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (_fd < 0) {
            throw std::runtime_error("socket failed");
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        if (::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
            throw std::runtime_error("inet_pton failed");
        }
        if (::connect(_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            throw std::runtime_error("connect failed");
        }
    }

    ~raw_socket() {
        if (_fd >= 0) {
            ::close(_fd);
        }
    }

    raw_socket(raw_socket const&) = delete;
    raw_socket& operator=(raw_socket const&) = delete;

    void send_all(std::string const& wire) {
        const char* data = wire.data();
        std::size_t remaining = wire.size();
        while (remaining) {
            const auto sent = ::send(_fd, data, remaining, 0);
            if (sent <= 0) {
                throw std::runtime_error("send failed");
            }
            data += sent;
            remaining -= static_cast<std::size_t>(sent);
        }
    }

    [[nodiscard]] std::string read_until(std::string const& marker,
                                         std::chrono::milliseconds budget = std::chrono::seconds(3)) {
        std::string out;
        const auto deadline = std::chrono::steady_clock::now() + budget;
        char buffer[4096];
        while (std::chrono::steady_clock::now() < deadline && out.find(marker) == std::string::npos) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(_fd, &fds);
            timeval tv{0, 50 * 1000};
            const auto ready = ::select(_fd + 1, &fds, nullptr, nullptr, &tv);
            if (ready < 0 && errno == EINTR) {
                continue;
            }
            if (ready < 0) {
                throw std::runtime_error("select failed");
            }
            if (ready == 0) {
                continue;
            }
            const auto n = ::recv(_fd, buffer, sizeof(buffer), 0);
            if (n <= 0) {
                break;
            }
            out.append(buffer, static_cast<std::size_t>(n));
        }
        return out;
    }

    [[nodiscard]] bool closes_within(std::chrono::milliseconds budget) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        char c;
        while (std::chrono::steady_clock::now() < deadline) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(_fd, &fds);
            timeval tv{0, 50 * 1000};
            const auto ready = ::select(_fd + 1, &fds, nullptr, nullptr, &tv);
            if (ready > 0) {
                const auto n = ::recv(_fd, &c, 1, MSG_PEEK);
                return n == 0;
            }
        }
        return false;
    }
};

} // namespace

TEST(Http1ClientTest, ConnectCallbackAndSequentialRequestsReuseOneConnection) {
    RunningHttp1Server server{33101};
    auto client = qb::http1::make_client(server.url("/"));

    bool connected = false;
    client->connect([&](bool ok, std::string const& error) {
        EXPECT_TRUE(ok) << error;
        connected = ok;
    });
    for (int i = 0; i < 200 && !connected; ++i) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    ASSERT_TRUE(connected);

    auto first = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));
    auto second = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/item/42")));

    EXPECT_EQ(first.status(), qb::http::status::OK);
    EXPECT_EQ(first.body().template as<std::string>(), "pong");
    EXPECT_EQ(second.status(), qb::http::status::OK);
    EXPECT_EQ(second.body().template as<std::string>(), "42");
    EXPECT_TRUE(client->is_connected());
    EXPECT_EQ(server.connection_count.load(), 1);
    EXPECT_EQ(server.request_count.load(), 2);
}

TEST(Http1ClientTest, CoroutineConnectAndSinglePostRequest) {
    RunningHttp1Server server{33102};
    auto client = qb::http1::make_client(server.url("/"));

    auto connect_result = qb::http::run_sync(client->connect());
    ASSERT_TRUE(connect_result) << connect_result.error_message;
    auto second_connect = qb::http::run_sync(client->connect());
    ASSERT_TRUE(second_connect) << second_connect.error_message;

    auto req = request(qb::http::method::POST, "/echo");
    req.body() = "hello-http1";
    auto response = qb::http::run_sync(client->push_request(std::move(req)));

    EXPECT_EQ(response.status(), qb::http::status::CREATED);
    EXPECT_EQ(response.body().template as<std::string>(), "hello-http1");
    EXPECT_TRUE(client->is_connected());
    EXPECT_EQ(server.connection_count.load(), 1);
}

TEST(Http1ClientTest, UserCallbacksMayReleaseLastClientReference) {
    RunningHttp1Server server{33112};

    {
        auto client = qb::http1::make_client(server.url("/"));
        bool connect_callback_called = false;
        client->connect([&](bool ok, std::string const&) {
            EXPECT_TRUE(ok);
            connect_callback_called = true;
            client.reset();
        });
        for (int i = 0; i < 200 && !connect_callback_called; ++i) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        EXPECT_TRUE(connect_callback_called);
    }

    {
        auto client = qb::http1::make_client(server.url("/"));
        bool response_callback_called = false;
        client->push_request(request(qb::http::method::GET, "/ping"),
            [&](qb::http::Response response) {
                EXPECT_EQ(response.status(), qb::http::status::OK);
                response_callback_called = true;
                client.reset();
            });
        for (int i = 0; i < 300 && !response_callback_called; ++i) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        EXPECT_TRUE(response_callback_called);
    }

    {
        auto client = qb::http1::make_client(server.url("/"));
        bool response_callback_called = false;
        client->push_request(request(qb::http::method::GET, "/ping"),
            [&](qb::http::Response response) {
                EXPECT_EQ(response.status(), qb::http::status::OK);
                response_callback_called = true;
                client->disconnect();
            });
        for (int i = 0; i < 300 && !response_callback_called; ++i) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        EXPECT_TRUE(response_callback_called);
        EXPECT_FALSE(client->is_connected());
    }

    {
        auto client = qb::http1::make_client(server.url("/"));
        qb::http::status response_status = qb::http::status::OK;
        bool response_callback_called = false;
        bool connect_callback_called = false;
        client->push_request(request(qb::http::method::GET, "/ping"),
            [&](qb::http::Response response) {
                response_status = response.status();
                response_callback_called = true;
            });
        client->connect([&](bool ok, std::string const&) {
            EXPECT_TRUE(ok);
            connect_callback_called = true;
            client->disconnect();
        });
        for (int i = 0; i < 300 && (!response_callback_called || !connect_callback_called); ++i) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        EXPECT_TRUE(connect_callback_called);
        EXPECT_TRUE(response_callback_called);
        EXPECT_EQ(response_status, qb::http::status::SERVICE_UNAVAILABLE);
        EXPECT_FALSE(client->is_connected());
    }
}

TEST(Http1ClientTest, BatchRequestsAreSequentialAndOrderPreserved) {
    RunningHttp1Server server{33103};
    auto client = qb::http1::make_client(server.url("/"));

    std::vector<qb::http::Request> requests;
    requests.emplace_back(request(qb::http::method::GET, "/item/1"));
    requests.emplace_back(request(qb::http::method::GET, "/item/2"));
    requests.emplace_back(request(qb::http::method::GET, "/item/3"));

    auto responses = qb::http::run_sync(client->push_requests(std::move(requests)));
    ASSERT_EQ(responses.size(), 3u);
    EXPECT_EQ(responses[0].body().template as<std::string>(), "1");
    EXPECT_EQ(responses[1].body().template as<std::string>(), "2");
    EXPECT_EQ(responses[2].body().template as<std::string>(), "3");
    EXPECT_EQ(server.connection_count.load(), 1);
    EXPECT_EQ(server.request_count.load(), 3);
}

TEST(Http1ClientTest, AbsoluteRequestWithExplicitDefaultPortMatchesBaseOrigin) {
    auto client = qb::http1::make_client("http://127.0.0.1");
    client->set_connect_timeout(0.2);

    auto response = qb::http::run_sync(client->push_request(
        request(qb::http::method::GET, "http://127.0.0.1:80/ping")));

    EXPECT_NE(response.status(), qb::http::status::BAD_REQUEST);
}

TEST(Http1ClientTest, SerializationFailureDoesNotBlockQueuedRequests) {
    RunningHttp1Server server{33108};
    auto client = qb::http1::make_client(server.url("/"));

    auto bad = request(qb::http::method::POST, "/echo");
    bad.body() = "too-long";
    bad.set_header("Content-Length", "1");

    std::vector<qb::http::Request> requests;
    requests.emplace_back(std::move(bad));
    requests.emplace_back(request(qb::http::method::GET, "/ping"));

    auto responses = qb::http::run_sync(client->push_requests(std::move(requests)));
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[1].status(), qb::http::status::OK);
    EXPECT_EQ(responses[1].body().template as<std::string>(), "pong");
    EXPECT_EQ(server.request_count.load(), 1);
}

TEST(Http1ClientTest, PendingRequestTimesOutBehindBlockedActiveRequest) {
    RunningHttp1Server server{33111};
    auto client = qb::http1::make_client(server.url("/"));
    client->set_request_timeout(0.05);

    std::vector<qb::http::Request> requests;
    requests.emplace_back(request(qb::http::method::GET, "/never"));
    requests.emplace_back(request(qb::http::method::GET, "/ping"));

    auto responses = qb::http::run_sync(client->push_requests(std::move(requests)));
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::GATEWAY_TIMEOUT);
    EXPECT_EQ(responses[1].status(), qb::http::status::REQUEST_TIMEOUT);
    EXPECT_EQ(server.request_count.load(), 1);
}

TEST(Http1ClientTest, ConnectionCloseResponseReconnectsBeforeNextRequest) {
    RunningHttp1Server server{33104};
    auto client = qb::http1::make_client(server.url("/"));

    auto closing = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/close")));
    EXPECT_EQ(closing.status(), qb::http::status::OK);
    EXPECT_EQ(closing.body().template as<std::string>(), "bye");

    auto after = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));
    EXPECT_EQ(after.status(), qb::http::status::OK);
    EXPECT_EQ(after.body().template as<std::string>(), "pong");
    EXPECT_GE(server.connection_count.load(), 2);
}

TEST(Http1ClientTest, HeadAndNoContentDoNotStealNextResponseBytes) {
    RunningHttp1Server server{33105};
    auto client = qb::http1::make_client(server.url("/"));

    auto head = qb::http::run_sync(client->push_request(request(qb::http::method::HEAD, "/head-length")));
    auto no_content = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/no-content")));
    auto ping = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));

    EXPECT_EQ(head.status(), qb::http::status::OK);
    EXPECT_EQ(head.header("Content-Length"), "123");
    EXPECT_TRUE(head.body().empty());
    EXPECT_EQ(no_content.status(), qb::http::status::NO_CONTENT);
    EXPECT_TRUE(no_content.body().empty());
    EXPECT_EQ(ping.status(), qb::http::status::OK);
    EXPECT_EQ(ping.body().template as<std::string>(), "pong");
    EXPECT_EQ(server.connection_count.load(), 1);
}

TEST(Http1ClientTest, Http10ClosesByDefaultButKeepAliveCanPersist) {
    RunningHttp1Server server{33106};

    {
        raw_socket socket{server.port};
        socket.send_all("GET /ping HTTP/1.0\r\nHost: localhost\r\n\r\n");
        const auto response = socket.read_until("pong");
        const auto lower = lowercase(response);
        EXPECT_NE(response.find("HTTP/1.1 200"), std::string::npos);
        EXPECT_NE(lower.find("connection: close"), std::string::npos);
        EXPECT_TRUE(socket.closes_within(std::chrono::seconds(2)));
    }

    {
        raw_socket socket{server.port};
        socket.send_all("GET /item/10 HTTP/1.0\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n");
        auto first = socket.read_until("10");
        EXPECT_NE(lowercase(first).find("connection: keep-alive"), std::string::npos);
        socket.send_all("GET /item/11 HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        auto second = socket.read_until("11");
        EXPECT_NE(second.find("11"), std::string::npos);
        EXPECT_TRUE(socket.closes_within(std::chrono::seconds(2)));
    }
}

TEST(Http1ClientTest, BackToBackHttp11RequestsAreAnsweredInRequestOrder) {
    RunningHttp1Server server{33107};
    raw_socket socket{server.port};

    socket.send_all(
        "GET /item/first HTTP/1.1\r\nHost: localhost\r\n\r\n"
        "GET /item/second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    const auto response = socket.read_until("second");
    const auto first_pos = response.find("first");
    const auto second_pos = response.find("second");

    ASSERT_NE(first_pos, std::string::npos);
    ASSERT_NE(second_pos, std::string::npos);
    EXPECT_LT(first_pos, second_pos);
    EXPECT_TRUE(socket.closes_within(std::chrono::seconds(2)));
    EXPECT_EQ(server.request_count.load(), 2);
}

TEST(Http1ClientTest, ExcessivePipelinedRequestsAreCapped) {
    RunningHttp1Server server{33109};
    raw_socket socket{server.port};

    std::string wire;
    for (int i = 0; i < 8; ++i) {
        wire += "GET /hold/";
        wire += std::to_string(i);
        wire += " HTTP/1.1\r\nHost: localhost\r\n\r\n";
    }
    socket.send_all(wire);

    EXPECT_TRUE(socket.closes_within(std::chrono::seconds(2)));
    EXPECT_LE(server.request_count.load(), 5);
}

TEST(Http1ClientTest, ConnectAwaiterReturnsErrorWhenClientExpiresBeforeAwait) {
    auto result = qb::io::async::run_sync([]() -> qb::io::async::task<qb::http1::ConnectResult> {
        auto client = qb::http1::make_client("http://127.0.0.1:1");
        auto awaiter = client->connect();
        client.reset();
        auto connect_result = co_await awaiter;
        co_return connect_result;
    }());

    EXPECT_FALSE(result.ok);
    EXPECT_FALSE(result.error_message.empty());
}

TEST(Http1ClientTest, ImplicitConnectFailureCompletesQueuedRequest) {
    auto client = qb::http1::make_client("http://127.0.0.1:1");
    client->set_connect_timeout(0.2);

    auto response = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));
    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_FALSE(response.body().empty());
    EXPECT_FALSE(client->is_connected());
}

TEST(Http1ClientTest, DestroyingClientDuringConnectDoesNotLeaveDanglingCallback) {
    {
        auto client = qb::http1::make_client("http://127.0.0.1:1");
        client->connect(nullptr);
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    while (std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    SUCCEED();
}

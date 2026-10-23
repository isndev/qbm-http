/**
 * @file tls-operations.cpp
 * @brief Server-factory TLS policy, rotation and listen contracts (QB-98).
 */
#include <chrono>
#include <concepts>
#include <string>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>
#include <qb/io/async.h>
#include <qb/io/tcp/ssl/socket.h>
#include <qbm/http/http.h>
#include <qbm/http/2/client.h>
#include <qbm/http/2/http2.h>
#include "../../shared/tls_identity.h"

namespace http_tls_operations_test {
using namespace std::chrono_literals;
using Context  = qb::io::ssl::Context;
using H1       = qb::http::ssl::Server<>;
using H2       = qb::http2::Server<>;
using Socket   = qb::io::tcp::ssl::socket;
using Identity = qb::http::test::tls_identity;

template <typename S>
concept tls_operations = requires(S &s, Context context, qb::io::uri uri, std::filesystem::path file) {
    { s.set_tls_context(context) } -> std::same_as<bool>;
    { s.reload_certificates(file, file) } -> std::same_as<bool>;
    { s.listen(uri, context) } -> std::same_as<bool>;
    { s.listen_no_start(uri, std::move(context)) } -> std::same_as<bool>;
};
static_assert(tls_operations<H1> && tls_operations<H2>);
static_assert(!tls_operations<qb::http::Server<>>);
static_assert(requires(qb::http::Server<> &s, qb::io::uri uri) {
    s.listen(uri, {});
    s.listen_no_start(uri, {});
});
static_assert(requires(H1 &s, qb::io::uri uri) {
    s.listen(uri, {});
    s.listen_no_start(uri, {}, {});
});
static_assert(requires(H2 &s, qb::io::uri uri) {
    s.listen(uri, {}, {});
    s.listen_no_start(uri, {}, {});
});

template <typename Predicate>
bool
pump_until(Predicate predicate, std::chrono::milliseconds budget = 5s) {
    const auto end = std::chrono::steady_clock::now() + budget;
    do {
        if (predicate())
            return true;
        qb::io::async::run_for(1ms);
    } while (std::chrono::steady_clock::now() < end);
    return predicate();
}

::testing::AssertionResult
connect_tcp(Socket &socket, uint16_t port, std::vector<std::string> protocols, std::string const &hostname = "localhost") {
    socket.set_insecure();
    if (!socket.set_alpn_protocols(protocols))
        return ::testing::AssertionFailure() << "ALPN offer failed";
    const auto result = socket.n_connect(qb::io::endpoint{"127.0.0.1", port}, hostname);
    if (result != 0 && !qb::io::socket_no_error(qb::io::socket::get_last_errno()))
        return ::testing::AssertionFailure() << "TCP connect failed";
    return ::testing::AssertionSuccess();
}

::testing::AssertionResult
handshake(Socket &socket) {
    int state = 0;
    if (!pump_until([&] {
            state = socket.handshake_status();
            return state != 0;
        })
        || state < 0)
        return ::testing::AssertionFailure() << "TLS handshake: " << socket.get_last_ssl_error_string();
    return ::testing::AssertionSuccess();
}

std::string
alpn(Socket const &socket) {
    unsigned char const *bytes = nullptr;
    unsigned int         size  = 0;
    SSL_get0_alpn_selected(socket.ssl_handle(), &bytes, &size);
    return size ? std::string(reinterpret_cast<char const *>(bytes), size) : std::string{};
}

void
expect_identity(Socket const &socket, std::string const &name) {
    EXPECT_EQ(socket.get_peer_certificate_details().subject, "/CN=" + name);
}

// Real HTTP/1.1 over the TLS socket, also used for the h2 listener's fallback.
// Content-Length and the full literal reply are checked; no sleep decides success.
::testing::AssertionResult
http1_exchange(Socket &socket) {
    constexpr std::string_view request = "GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n";
    std::size_t                sent    = 0;
    std::string                response;
    if (!pump_until([&] {
            if (sent < request.size()) {
                const auto n = socket.write(request.data() + sent, request.size() - sent);
                if (n > 0)
                    sent += static_cast<std::size_t>(n);
            }
            char       bytes[2048];
            const auto n = socket.read(bytes, sizeof(bytes));
            if (n > 0)
                response.append(bytes, static_cast<std::size_t>(n));
            return response.ends_with("\r\n\r\npong");
        }))
        return ::testing::AssertionFailure() << "HTTP reply incomplete: " << response;
    if (!response.starts_with("HTTP/1.1 200") || response.find("content-length: 4") == std::string::npos)
        return ::testing::AssertionFailure() << "Unexpected HTTP reply: " << response;
    return ::testing::AssertionSuccess();
}

template <typename S>
class TlsOperations : public ::testing::Test {
protected:
    void
    SetUp() override {
        qb::io::async::init();
    }
    void
    TearDown() override {
        qb::io::async::listener::current.clear();
    }
    static void
    route(S &server) {
        server.router().get("/ping", [](auto ctx) { ctx->text("pong"); });
        server.router().compile();
    }
    static std::vector<std::string>
    protocols() {
        if constexpr (std::is_same_v<S, H2>)
            return {"h2", "http/1.1"};
        return {"http/1.1"};
    }
};
using ServerTypes = ::testing::Types<H1, H2>;
TYPED_TEST_SUITE(TlsOperations, ServerTypes);

TYPED_TEST(TlsOperations, RotationKeepsEstablishedAndAcceptedConnections) {
    Identity first{"before"}, second{"after"};
    ASSERT_TRUE(first.ok() && second.ok());
    TypeParam server;
    this->route(server);
    auto initial = first.context().alpn({"wrong"});
    ASSERT_TRUE(server.listen(qb::io::uri{"tcp://127.0.0.1:0"}, initial));
    const auto port = server.transport().local_endpoint().port();
    Socket     established;
    ASSERT_TRUE(connect_tcp(established, port, {"http/1.1"}));
    ASSERT_TRUE(handshake(established));
    expect_identity(established, "before");
    EXPECT_EQ(alpn(established), "http/1.1");
    // The h2 server's h1 fallback serves one response then closes by contract.
    // Its native h2 keepalive is exercised separately below.
    if constexpr (std::is_same_v<TypeParam, H1>) {
        ASSERT_TRUE(http1_exchange(established));
    }

    // Accept without sending ClientHello. The server has minted its SSL on the old
    // context, so a subsequent handshake must still present the old certificate.
    Socket pending;
    ASSERT_TRUE(connect_tcp(pending, port, {"http/1.1"}));
    ASSERT_TRUE(pump_until([&] { return server.session_count() == 2; }));
    ASSERT_FALSE(pending.handshake_complete());
    ASSERT_TRUE(server.reload_certificates(second.cert(), second.key()));
    EXPECT_EQ(server.transport().local_endpoint().port(), port);
    ASSERT_TRUE(handshake(pending));
    expect_identity(pending, "before");
    EXPECT_EQ(alpn(pending), "http/1.1");
    ASSERT_TRUE(http1_exchange(pending));
    ASSERT_TRUE(http1_exchange(established));
    Socket fresh;
    ASSERT_TRUE(connect_tcp(fresh, port, {"http/1.1"}));
    ASSERT_TRUE(handshake(fresh));
    expect_identity(fresh, "after");
    ASSERT_TRUE(http1_exchange(fresh));
}

TYPED_TEST(TlsOperations, InvalidRenewalsLeaveTheServingContextIntact) {
    Identity current{"current"}, replacement{"replacement"};
    ASSERT_TRUE(current.ok() && replacement.ok());
    TypeParam server;
    this->route(server);
    ASSERT_TRUE(server.listen(qb::io::uri{"tcp://127.0.0.1:0"}, current.context()));
    auto *const serving = server.transport().context().native();
    EXPECT_FALSE(server.set_tls_context(Context{}));
    EXPECT_FALSE(server.reload_certificates(replacement.cert(), current.key()));
    EXPECT_FALSE(server.reload_certificates(current.cert().string() + ".missing", current.key()));
    EXPECT_FALSE(server.reload_certificates({}, {}));
    EXPECT_EQ(server.transport().context().native(), serving);
    Socket next;
    ASSERT_TRUE(connect_tcp(next, server.transport().local_endpoint().port(), {"http/1.1"}));
    ASSERT_TRUE(handshake(next));
    expect_identity(next, "current");
    ASSERT_TRUE(http1_exchange(next));
}

TYPED_TEST(TlsOperations, AdoptedAndSharedServerContextsPinServerAlpn) {
    Identity identity{"raw-context"};
    ASSERT_TRUE(identity.ok());
    for (auto *method : {TLS_server_method(), TLS_method()}) {
        for (bool share : {false, true}) {
            std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> raw{SSL_CTX_new(method), SSL_CTX_free};
            ASSERT_NE(raw, nullptr);
            auto context = share ? Context::share(raw.get()) : Context::adopt(raw.release());
            context.identity(identity.cert(), identity.key()).alpn({"incorrect"});
            ASSERT_TRUE(context.ok()) << context.error();
            TypeParam server;
            ASSERT_TRUE(server.listen(qb::io::uri{"tcp://127.0.0.1:0"}, context));
            Socket client;
            ASSERT_TRUE(connect_tcp(client, server.transport().local_endpoint().port(), {"http/1.1", "h2"}));
            ASSERT_TRUE(handshake(client));
            expect_identity(client, "raw-context");
            EXPECT_EQ(alpn(client), this->protocols().front());
        }
    }
}

TYPED_TEST(TlsOperations, ClientAndDatagramContextsAreRefusedBeforePublication) {
    Identity identity{"serving"};
    ASSERT_TRUE(identity.ok());
    TypeParam server;
    this->route(server);
    ASSERT_TRUE(server.listen(qb::io::uri{"tcp://127.0.0.1:0"}, identity.context()));
    auto *const serving = server.transport().context().native();
    auto        client  = Context::client();
    ASSERT_TRUE(client.ok());
    EXPECT_FALSE(server.set_tls_context(client));
    EXPECT_EQ(server.transport().context().native(), serving);
    client = Context::client().identity(identity.cert(), identity.key());
    ASSERT_TRUE(client.ok());
    EXPECT_FALSE(server.set_tls_context(client));
    EXPECT_EQ(server.transport().context().native(), serving);
    auto datagram = Context::adopt(SSL_CTX_new(DTLS_server_method())).identity(identity.cert(), identity.key());
    ASSERT_TRUE(datagram.ok());
    EXPECT_FALSE(server.set_tls_context(datagram));
    ASSERT_EQ(server.transport().context().native(), serving);
    Socket next;
    ASSERT_TRUE(connect_tcp(next, server.transport().local_endpoint().port(), {"http/1.1"}));
    ASSERT_TRUE(handshake(next));
    expect_identity(next, "serving");
    ASSERT_TRUE(http1_exchange(next));
}

TYPED_TEST(TlsOperations, FreshContextPreservesPolicyAndCertificateSugarRestoresDefaults) {
    Identity first{"policy"}, next{"defaults"};
    ASSERT_TRUE(first.ok() && next.ok());
    int       keylog_lines = 0;
    TypeParam server;
    auto      context = first.context();
    context.verify(qb::io::ssl::VerifyMode::peer)
        .min_version(qb::io::ssl::TlsVersion::v1_3)
        .alpn({"incorrect"})
        .on_keylog([&](std::string_view) { ++keylog_lines; });
    ASSERT_TRUE(server.listen(qb::io::uri{"tcp://127.0.0.1:0"}, context));
    EXPECT_EQ(SSL_CTX_get_verify_mode(server.transport().context().native()), SSL_VERIFY_PEER);
    EXPECT_EQ(SSL_CTX_get_min_proto_version(server.transport().context().native()), TLS1_3_VERSION);
    EXPECT_NE(SSL_CTX_get_keylog_callback(server.transport().context().native()), nullptr);
    Socket old;
    ASSERT_TRUE(connect_tcp(old, server.transport().local_endpoint().port(), {"http/1.1", "h2"}));
    ASSERT_TRUE(handshake(old));
    EXPECT_EQ(alpn(old), this->protocols().front());
    EXPECT_GT(keylog_lines, 0);
    ASSERT_TRUE(server.reload_certificates(next.cert(), next.key()));
    EXPECT_EQ(SSL_CTX_get_verify_mode(server.transport().context().native()), SSL_VERIFY_NONE);
    EXPECT_EQ(SSL_CTX_get_min_proto_version(server.transport().context().native()), TLS1_2_VERSION);
    EXPECT_EQ(SSL_CTX_get_keylog_callback(server.transport().context().native()), nullptr);
    Socket fresh;
    ASSERT_TRUE(connect_tcp(fresh, server.transport().local_endpoint().port(), {"http/1.1", "h2"}));
    ASSERT_TRUE(handshake(fresh));
    expect_identity(fresh, "defaults");
    EXPECT_EQ(alpn(fresh), this->protocols().front());
}

TYPED_TEST(TlsOperations, SniTableAndFallbackRotateWithTheirContexts) {
    Identity fallback{"fallback"}, a{"host-a"}, b{"host-b"}, renewed{"renewed"};
    ASSERT_TRUE(fallback.ok() && a.ok() && b.ok() && renewed.ok());
    TypeParam  server;
    const auto protocols  = this->protocols();
    auto       make_table = [&](bool swapped) {
        auto one  = (swapped ? b.context() : a.context()).alpn(protocols);
        auto two  = (swapped ? a.context() : b.context()).alpn(protocols);
        auto root = swapped ? renewed.context() : fallback.context();
        root.on_sni([one, two](std::string_view hostname) {
            if (hostname == "a.test")
                return one;
            if (hostname == "b.test")
                return two;
            return Context{}; // retain the root context for an unknown name
        });
        return root;
    };
    ASSERT_TRUE(server.listen(qb::io::uri{"tcp://127.0.0.1:0"}, make_table(false)));
    const auto port = server.transport().local_endpoint().port();
    Socket     pending;
    for (bool rotated : {false, true}) {
        if (rotated) {
            ASSERT_TRUE(pump_until([&] { return server.session_count() == 0; }));
            ASSERT_TRUE(connect_tcp(pending, port, {"http/1.1", "h2"}, "a.test"));
            ASSERT_TRUE(pump_until([&] { return server.session_count() == 1; }));
            ASSERT_TRUE(server.set_tls_context(make_table(true)));
            ASSERT_TRUE(handshake(pending));
            expect_identity(pending, "host-a");
            EXPECT_EQ(alpn(pending), protocols.front());
        }
        for (auto const &host : {"a.test", "b.test", "unknown.test"}) {
            Socket socket;
            ASSERT_TRUE(connect_tcp(socket, port, {"http/1.1", "h2"}, host));
            ASSERT_TRUE(handshake(socket));
            expect_identity(socket, std::string_view{host} == "a.test"   ? (rotated ? "host-b" : "host-a")
                                    : std::string_view{host} == "b.test" ? (rotated ? "host-a" : "host-b")
                                                                         : (rotated ? "renewed" : "fallback"));
            EXPECT_EQ(alpn(socket), protocols.front());
        }
    }
}

TYPED_TEST(TlsOperations, ContextListenNoStartDefersAcceptAndStartRemainsIdempotent) {
    Identity identity{"deferred"};
    ASSERT_TRUE(identity.ok());
    TypeParam server;
    this->route(server);
    ASSERT_TRUE(server.listen_no_start(qb::io::uri{"tcp://127.0.0.1:0"}, identity.context()));
    Socket client;
    ASSERT_TRUE(connect_tcp(client, server.transport().local_endpoint().port(), {"http/1.1"}));
    EXPECT_FALSE(pump_until([&] { return server.session_count() != 0; }, 25ms));
    server.start();
    server.start();
    ASSERT_TRUE(handshake(client));
    ASSERT_TRUE(http1_exchange(client));
}

TEST(HttpTlsOperations, Http2KeepAliveContinuesAcrossRotation) {
    qb::io::async::init();
    {
        Identity first{"h2-before"}, second{"h2-after"};
        ASSERT_TRUE(first.ok() && second.ok());
        auto server = qb::http2::make_server();
        server->router().get("/ping", [](auto ctx) { ctx->text(uuids::to_string(ctx->session()->id())); });
        server->router().compile();
        ASSERT_TRUE(server->listen(qb::io::uri{"tcp://127.0.0.1:0"}, first.context()));
        const auto origin = "https://localhost:" + std::to_string(server->transport().local_endpoint().port());
        auto       client = qb::http2::make_client(origin);
        client->set_verify_peer(false);
        auto request = [&]() {
            struct Result {
                bool               done = false;
                qb::http::Response response;
            };
            auto result = std::make_shared<Result>();
            EXPECT_TRUE(client->push_request(qb::http::Request{{origin + "/ping"}}, [result](qb::http::Response r) {
                result->response = std::move(r);
                result->done     = true;
            }));
            client->connect(nullptr);
            EXPECT_TRUE(pump_until([&] { return result->done; }));
            EXPECT_EQ(result->response.status(), qb::http::status::OK);
            return result->response.body().as<std::string>();
        };
        const auto session = request();
        ASSERT_FALSE(session.empty());
        ASSERT_TRUE(server->reload_certificates(second.cert(), second.key()));
        EXPECT_EQ(request(), session);
        EXPECT_EQ(server->session_count(), 1u);
        client->disconnect();
    }
    qb::io::async::listener::current.clear();
}

} // namespace http_tls_operations_test

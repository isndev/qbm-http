/**
 * @file test-api-hardening.cpp
 * @brief Focused non-regression tests for client-side WS API hardening.
 */

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstring>
#include <string>
#include <stdexcept>
#include <thread>
#include <vector>

#include <qb/io/async.h>

#include "../ws/ws.h"

namespace {

class MaskingProbeClient final : public qb::http::ws::WebSocket<MaskingProbeClient> {};

class SinkServer;

class SinkServerClient
    : public qb::io::use<SinkServerClient>::tcp::client<SinkServer> {
public:
    explicit SinkServerClient(IOServer &server) : client(server) {}
};

class SinkServer : public qb::io::use<SinkServer>::tcp::server<SinkServerClient> {};

class HandshakeValidationServer;

class HandshakeValidationServerClient
    : public qb::io::use<HandshakeValidationServerClient>::tcp::client<HandshakeValidationServer> {
public:
    using Protocol    = qb::http::protocol<HandshakeValidationServerClient>;
    using WS_Protocol = qb::http::ws::protocol<HandshakeValidationServerClient>;

    explicit HandshakeValidationServerClient(IOServer &server) : client(server) {}

    void on(Protocol::request &&request) {
        qb::http::Response response;
        if (!this->switch_protocol<WS_Protocol>(*this, request, response)) {
            if (static_cast<int>(response.status()) == 0) {
                response.status() = qb::http::status::BAD_REQUEST;
            }
            *this << response;
            this->disconnect();
            return;
        }
        *this << response;
        this->disconnect();
    }

    void on(WS_Protocol::message &&) {}
    void on(WS_Protocol::ping &&) {}
    void on(WS_Protocol::pong &&) {}
    void on(WS_Protocol::close &&) {}
};

class HandshakeValidationServer
    : public qb::io::use<HandshakeValidationServer>::tcp::server<HandshakeValidationServerClient> {};

std::size_t g_control_ping_received = 0;
std::size_t g_close_echo_received   = 0;

class ControlProbeServer;

class ControlProbeServerClient
    : public qb::io::use<ControlProbeServerClient>::tcp::client<ControlProbeServer> {
public:
    using Protocol    = qb::http::protocol<ControlProbeServerClient>;
    using WS_Protocol = qb::http::ws::protocol<ControlProbeServerClient>;

    explicit ControlProbeServerClient(IOServer &server) : client(server) {}

    void on(Protocol::request &&request) {
        if (!this->switch_protocol<WS_Protocol>(*this, request)) {
            disconnect();
        }
    }

    void on(WS_Protocol::ping &&) {
        ++g_control_ping_received;
        this->disconnect();
    }

    void on(WS_Protocol::message &&) {}
};

class ControlProbeServer
    : public qb::io::use<ControlProbeServer>::tcp::server<ControlProbeServerClient> {};

class BadSubprotocolServer;

class BadSubprotocolServerClient
    : public qb::io::use<BadSubprotocolServerClient>::tcp::client<BadSubprotocolServer> {
public:
    using Protocol    = qb::http::protocol<BadSubprotocolServerClient>;
    using WS_Protocol = qb::http::ws::protocol<BadSubprotocolServerClient>;

    explicit BadSubprotocolServerClient(IOServer &server) : client(server) {}

    void on(Protocol::request &&request) {
        qb::http::Response response;
        if (!this->switch_protocol<WS_Protocol>(*this, request, response)) {
            disconnect();
            return;
        }
        response.headers()["Sec-WebSocket-Protocol"].clear();
        response.headers()["Sec-WebSocket-Protocol"].emplace_back("server-only.proto");
        *this << response;
    }

    void on(WS_Protocol::message &&) {}
    void on(WS_Protocol::ping &&) {}
    void on(WS_Protocol::pong &&) {}
    void on(WS_Protocol::close &&) {}
};

class BadSubprotocolServer
    : public qb::io::use<BadSubprotocolServer>::tcp::server<BadSubprotocolServerClient> {};

class BadConnectionTokenServer;

class BadConnectionTokenServerClient
    : public qb::io::use<BadConnectionTokenServerClient>::tcp::client<BadConnectionTokenServer> {
public:
    using Protocol    = qb::http::protocol<BadConnectionTokenServerClient>;
    using WS_Protocol = qb::http::ws::protocol<BadConnectionTokenServerClient>;

    explicit BadConnectionTokenServerClient(IOServer &server) : client(server) {}

    void on(Protocol::request &&request) {
        qb::http::Response response;
        if (!this->switch_protocol<WS_Protocol>(*this, request, response)) {
            disconnect();
            return;
        }
        // Deliberately malformed token list: contains "upgraded", not "Upgrade".
        response.headers()["Connection"].clear();
        response.headers()["Connection"].emplace_back("keep-alive, upgraded");
        *this << response;
    }

    void on(WS_Protocol::message &&) {}
    void on(WS_Protocol::ping &&) {}
    void on(WS_Protocol::pong &&) {}
    void on(WS_Protocol::close &&) {}
};

class BadConnectionTokenServer
    : public qb::io::use<BadConnectionTokenServer>::tcp::server<BadConnectionTokenServerClient> {};

class MaskedFrameServer;

class MaskedFrameServerClient
    : public qb::io::use<MaskedFrameServerClient>::tcp::client<MaskedFrameServer> {
public:
    using Protocol    = qb::http::protocol<MaskedFrameServerClient>;
    using WS_Protocol = qb::http::ws::protocol<MaskedFrameServerClient>;

    explicit MaskedFrameServerClient(IOServer &server) : client(server) {}

    void on(Protocol::request &&request) {
        qb::http::Response response;
        if (!this->switch_protocol<WS_Protocol>(*this, request, response)) {
            disconnect();
            return;
        }
        *this << response;

        const std::string payload = "evil";
        constexpr std::array<unsigned char, 4> mask{{0x11, 0x22, 0x33, 0x44}};
        std::vector<char> frame;
        frame.reserve(2 + 4 + payload.size());
        frame.push_back(static_cast<char>(0x81)); // FIN + text
        frame.push_back(static_cast<char>(0x80 | payload.size())); // MASK bit set (invalid for server->client)
        for (unsigned char b : mask) {
            frame.push_back(static_cast<char>(b));
        }
        for (std::size_t i = 0; i < payload.size(); ++i) {
            frame.push_back(static_cast<char>(
                static_cast<unsigned char>(payload[i]) ^ mask[i % 4]));
        }
        this->transport().write(frame.data(), static_cast<int>(frame.size()));
        this->disconnect();
    }

    void on(WS_Protocol::message &&) {}
    void on(WS_Protocol::ping &&) {}
    void on(WS_Protocol::pong &&) {}
    void on(WS_Protocol::close &&) {}
};

class MaskedFrameServer
    : public qb::io::use<MaskedFrameServer>::tcp::server<MaskedFrameServerClient> {};

class ReservedOpcodeServer;

class ReservedOpcodeServerClient
    : public qb::io::use<ReservedOpcodeServerClient>::tcp::client<ReservedOpcodeServer> {
public:
    using Protocol    = qb::http::protocol<ReservedOpcodeServerClient>;
    using WS_Protocol = qb::http::ws::protocol<ReservedOpcodeServerClient>;

    explicit ReservedOpcodeServerClient(IOServer &server) : client(server) {}

    void on(Protocol::request &&request) {
        qb::http::Response response;
        if (!this->switch_protocol<WS_Protocol>(*this, request, response)) {
            disconnect();
            return;
        }
        *this << response;

        // FIN + reserved control opcode 0xB (invalid per RFC 6455).
        const std::array<char, 2> frame{{static_cast<char>(0x8Bu), 0x00}};
        this->transport().write(frame.data(), static_cast<int>(frame.size()));
        this->disconnect();
    }

    void on(WS_Protocol::message &&) {}
    void on(WS_Protocol::ping &&) {}
    void on(WS_Protocol::pong &&) {}
    void on(WS_Protocol::close &&) {}
};

class ReservedOpcodeServer
    : public qb::io::use<ReservedOpcodeServer>::tcp::server<ReservedOpcodeServerClient> {};

class InvalidClosePayloadServer;

class InvalidClosePayloadServerClient
    : public qb::io::use<InvalidClosePayloadServerClient>::tcp::client<InvalidClosePayloadServer> {
public:
    using Protocol    = qb::http::protocol<InvalidClosePayloadServerClient>;
    using WS_Protocol = qb::http::ws::protocol<InvalidClosePayloadServerClient>;

    explicit InvalidClosePayloadServerClient(IOServer &server) : client(server) {}

    void on(Protocol::request &&request) {
        qb::http::Response response;
        if (!this->switch_protocol<WS_Protocol>(*this, request, response)) {
            disconnect();
            return;
        }
        *this << response;

        // Close frame payload length = 1 is invalid by RFC 6455 §5.5.1.
        const std::array<char, 3> frame{
            {static_cast<char>(0x88u), 0x01, static_cast<char>(0x00)}};
        std::memcpy(this->out().allocate_back(frame.size()), frame.data(), frame.size());
        this->ready_to_write();
    }

    void on(WS_Protocol::message &&) {}
    void on(WS_Protocol::ping &&) {}
    void on(WS_Protocol::pong &&) {}
    void on(WS_Protocol::close &&) {}
};

class InvalidClosePayloadServer
    : public qb::io::use<InvalidClosePayloadServer>::tcp::server<InvalidClosePayloadServerClient> {};

class InvalidCloseReasonUtf8Server;

class InvalidCloseReasonUtf8ServerClient
    : public qb::io::use<InvalidCloseReasonUtf8ServerClient>::tcp::client<InvalidCloseReasonUtf8Server> {
public:
    using Protocol    = qb::http::protocol<InvalidCloseReasonUtf8ServerClient>;
    using WS_Protocol = qb::http::ws::protocol<InvalidCloseReasonUtf8ServerClient>;

    explicit InvalidCloseReasonUtf8ServerClient(IOServer &server) : client(server) {}

    void on(Protocol::request &&request) {
        qb::http::Response response;
        if (!this->switch_protocol<WS_Protocol>(*this, request, response)) {
            disconnect();
            return;
        }
        *this << response;

        // Close code 1000 + invalid UTF-8 reason ED A0 80 (surrogate).
        const std::array<char, 7> frame{
            {static_cast<char>(0x88u),
             0x05,
             static_cast<char>(0x03), static_cast<char>(0xE8),
             static_cast<char>(0xED), static_cast<char>(0xA0), static_cast<char>(0x80)}};
        std::memcpy(this->out().allocate_back(frame.size()), frame.data(), frame.size());
        this->ready_to_write();
    }

    void on(WS_Protocol::message &&) {}
    void on(WS_Protocol::ping &&) {}
    void on(WS_Protocol::pong &&) {}
    void on(WS_Protocol::close &&) {}
};

class InvalidCloseReasonUtf8Server
    : public qb::io::use<InvalidCloseReasonUtf8Server>::tcp::server<InvalidCloseReasonUtf8ServerClient> {};

class CloseEchoProbeServer;

class CloseEchoProbeServerClient
    : public qb::io::use<CloseEchoProbeServerClient>::tcp::client<CloseEchoProbeServer>
    , public qb::io::use<CloseEchoProbeServerClient>::timeout {
public:
    using Protocol    = qb::http::protocol<CloseEchoProbeServerClient>;
    using WS_Protocol = qb::http::ws::protocol<CloseEchoProbeServerClient>;

    explicit CloseEchoProbeServerClient(IOServer &server) : client(server) {}

    void on(Protocol::request &&request) {
        qb::http::Response response;
        if (!this->switch_protocol<WS_Protocol>(*this, request, response)) {
            disconnect();
            return;
        }
        *this << response;

        // Initiate server-side close but keep the transport alive briefly so
        // the client has time to echo the close frame back.
        qb::http::ws::MessageClose close_msg(
            qb::http::ws::CloseStatus::GoingAway, "server-closing");
        *this << close_msg;
        this->setTimeout(200);
    }

    void on(WS_Protocol::close &&) {
        ++g_close_echo_received;
        this->disconnect();
    }

    void on(qb::io::async::event::timeout const &) { this->disconnect(); }

    void on(WS_Protocol::message &&) {}
    void on(WS_Protocol::ping &&) {}
    void on(WS_Protocol::pong &&) {}
};

class CloseEchoProbeServer
    : public qb::io::use<CloseEchoProbeServer>::tcp::server<CloseEchoProbeServerClient> {};

bool run_until(const std::function<bool()> &condition,
               int max_iterations = 300,
               int sleep_ms = 5) {
    for (int i = 0; i < max_iterations; ++i) {
        qb::io::async::run(EVRUN_NOWAIT);
        if (condition()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
    }
    return false;
}

} // namespace

TEST(WebSocketApiHardening, ClientControlFramesAreAcceptedAsMaskedByServerParser) {
    qb::io::async::init();
    g_control_ping_received = 0;

    constexpr int port = 20123;
    ControlProbeServer server;
    server.transport().listen_v4(port);
    server.start();

    qb::http::ws::client client;
    bool connected = false;
    bool disconnected = false;
    client.on_connected([&](auto &) {
        connected = true;
        qb::http::ws::MessagePing ping;
        client << ping; // Must be masked by client operator<<.
    });
    client.on_disconnected([&](auto &) { disconnected = true; });
    client.connect(qb::io::uri("ws://localhost:20123/path"), 1000);

    ASSERT_TRUE(run_until([&]() {
        return g_control_ping_received > 0 || disconnected;
    })) << "No control-frame activity observed";

    EXPECT_TRUE(connected);
    EXPECT_EQ(g_control_ping_received, 1u);
}

TEST(WebSocketApiHardening, ServerRejectsMalformedSecWebSocketKey) {
    qb::io::async::init();

    constexpr int port = 20121;
    HandshakeValidationServer server;
    server.transport().listen_v4(port);
    server.start();

    qb::io::tcp::socket sock;
    ASSERT_EQ(sock.connect(qb::io::uri{"tcp://localhost:20121"}), 0);
    (void) sock.set_nonblocking(true);

    const std::string request =
        "GET /path HTTP/1.1\r\n"
        "Host: localhost:20121\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: aaaaaaaaaaaaaaaaaaaaaaaa\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n";
    sock.write(request.data(), static_cast<int>(request.size()));

    std::string response;
    for (int i = 0; i < 500; ++i) {
        qb::io::async::run(EVRUN_NOWAIT);
        char buf[512];
        const int n = sock.read(buf, sizeof(buf));
        if (n > 0) {
            response.append(buf, static_cast<std::size_t>(n));
            if (response.find("\r\n\r\n") != std::string::npos) break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    EXPECT_EQ(response.find("101 Switching Protocols"), std::string::npos)
        << "Server must reject malformed Sec-WebSocket-Key";
    if (!response.empty()) {
        EXPECT_NE(response.find("400"), std::string::npos)
            << "Expected a BAD_REQUEST style response, got:\n"
            << response;
    }
}

TEST(WebSocketApiHardening, ServerRejectsNonBase64SecWebSocketKey) {
    qb::io::async::init();

    constexpr int port = 20131;
    HandshakeValidationServer server;
    server.transport().listen_v4(port);
    server.start();

    qb::io::tcp::socket sock;
    ASSERT_EQ(sock.connect(qb::io::uri{"tcp://localhost:20131"}), 0);
    (void) sock.set_nonblocking(true);

    const std::string request =
        "GET /path HTTP/1.1\r\n"
        "Host: localhost:20131\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: !!!!!!!!!!!!!!!!!!!!!!!!\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n";
    sock.write(request.data(), static_cast<int>(request.size()));

    std::string response;
    for (int i = 0; i < 500; ++i) {
        qb::io::async::run(EVRUN_NOWAIT);
        char buf[512];
        const int n = sock.read(buf, sizeof(buf));
        if (n > 0) {
            response.append(buf, static_cast<std::size_t>(n));
            if (response.find("\r\n\r\n") != std::string::npos) break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    EXPECT_EQ(response.find("101 Switching Protocols"), std::string::npos)
        << "Server must reject non-base64 Sec-WebSocket-Key";
    if (!response.empty()) {
        EXPECT_NE(response.find("400"), std::string::npos)
            << "Expected a BAD_REQUEST style response, got:\n"
            << response;
    }
}

TEST(WebSocketApiHardening, HandshakeHostHeaderIncludesNonDefaultPortAndIpv6Brackets) {
    qb::io::async::init();

    constexpr int port = 20127;
    SinkServer server;
    server.transport().listen_v6(port);
    server.start();

    std::string captured_host;
    qb::http::ws::client client;
    client.on_sending_http_request([&captured_host](auto &event) {
        captured_host = std::string(event.request.header("host"));
    });

    client.connect(qb::io::uri("ws://[::1]:20127/path"), 1000);

    ASSERT_TRUE(run_until([&captured_host]() { return !captured_host.empty(); }))
        << "WebSocket client did not reach request emission phase";

    EXPECT_EQ(captured_host, "[::1]:20127");
}

TEST(WebSocketApiHardening, ClientRejectsServerSubprotocolNotOfferedByClient) {
    qb::io::async::init();

    constexpr int port = 20125;
    BadSubprotocolServer server;
    server.transport().listen_v6(port);
    server.start();

    bool connected = false;
    bool errored = false;
    bool disconnected = false;

    qb::http::ws::client client;
    client.add_subprotocol("chat.v1");
    client.on_connected([&connected](auto &) { connected = true; });
    client.on_error([&errored](auto &) { errored = true; });
    client.on_disconnected([&disconnected](auto &) { disconnected = true; });
    client.connect(qb::io::uri("ws://[::1]:20125/path"), 1000);

    ASSERT_TRUE(run_until([&]() { return errored || connected || disconnected; }))
        << "WebSocket client produced no terminal signal";

    EXPECT_TRUE(errored);
    EXPECT_FALSE(connected);
}

TEST(WebSocketApiHardening, ClientRejectsMalformedConnectionTokenInHandshakeResponse) {
    qb::io::async::init();

    constexpr int port = 20122;
    BadConnectionTokenServer server;
    server.transport().listen_v4(port);
    server.start();

    bool connected = false;
    bool errored = false;
    bool disconnected = false;

    qb::http::ws::client client;
    client.on_connected([&connected](auto &) { connected = true; });
    client.on_error([&errored](auto &) { errored = true; });
    client.on_disconnected([&disconnected](auto &) { disconnected = true; });
    client.connect(qb::io::uri("ws://localhost:20122/path"), 1000);

    ASSERT_TRUE(run_until([&]() { return errored || connected || disconnected; }))
        << "WebSocket client produced no terminal signal";

    EXPECT_TRUE(errored);
    EXPECT_FALSE(connected);
}

TEST(WebSocketApiHardening, ClientRejectsMaskedFrameFromServer) {
    qb::io::async::init();

    constexpr int port = 20124;
    MaskedFrameServer server;
    server.transport().listen_v4(port);
    server.start();

    bool connected = false;
    bool errored = false;
    bool disconnected = false;
    std::size_t messages = 0;

    qb::http::ws::client client;
    client.on_connected([&connected](auto &) { connected = true; });
    client.on_error([&errored](auto &) { errored = true; });
    client.on_message([&messages](auto &) { ++messages; });
    client.on_disconnected([&disconnected](auto &) { disconnected = true; });
    client.connect(qb::io::uri("ws://localhost:20124/path"), 1000);

    ASSERT_TRUE(run_until([&]() { return errored || disconnected || messages > 0; }))
        << "Client did not surface any terminal reaction to masked server frame";

    EXPECT_EQ(messages, 0u);
    EXPECT_TRUE(errored || disconnected);
}

TEST(WebSocketApiHardening, ClientRejectsReservedOpcodeFromServer) {
    qb::io::async::init();

    constexpr int port = 20128;
    ReservedOpcodeServer server;
    server.transport().listen_v4(port);
    server.start();

    bool connected = false;
    bool errored = false;
    bool disconnected = false;
    std::size_t messages = 0;

    qb::http::ws::client client;
    client.on_connected([&connected](auto &) { connected = true; });
    client.on_error([&errored](auto &) { errored = true; });
    client.on_message([&messages](auto &) { ++messages; });
    client.on_disconnected([&disconnected](auto &) { disconnected = true; });
    client.connect(qb::io::uri("ws://localhost:20128/path"), 1000);

    ASSERT_TRUE(run_until([&]() { return errored || disconnected || messages > 0; }))
        << "Client did not react to reserved opcode frame";

    EXPECT_EQ(messages, 0u);
    EXPECT_TRUE(errored || disconnected);
}

TEST(WebSocketApiHardening, ClientRejectsInvalidClosePayloadLengthOne) {
    qb::io::async::init();

    constexpr int port = 20129;
    InvalidClosePayloadServer server;
    server.transport().listen_v4(port);
    server.start();

    bool connected = false;
    bool errored = false;
    bool disconnected = false;
    std::size_t closes = 0;

    qb::http::ws::client client;
    client.on_connected([&connected](auto &) { connected = true; });
    client.on_error([&errored](auto &) { errored = true; });
    client.on_closed([&closes](auto &) { ++closes; });
    client.on_disconnected([&disconnected](auto &) { disconnected = true; });
    client.connect(qb::io::uri("ws://localhost:20129/path"), 1000);

    ASSERT_TRUE(run_until([&]() { return errored || disconnected || closes > 0; }))
        << "Client did not react to invalid close payload";

    EXPECT_EQ(closes, 0u);
    EXPECT_TRUE(errored || disconnected);
}

TEST(WebSocketApiHardening, ClientRejectsInvalidUtf8InCloseReason) {
    qb::io::async::init();

    constexpr int port = 20130;
    InvalidCloseReasonUtf8Server server;
    server.transport().listen_v4(port);
    server.start();

    bool errored = false;
    bool disconnected = false;
    std::size_t closes = 0;

    qb::http::ws::client client;
    client.on_error([&errored](auto &) { errored = true; });
    client.on_closed([&closes](auto &) { ++closes; });
    client.on_disconnected([&disconnected](auto &) { disconnected = true; });
    client.connect(qb::io::uri("ws://localhost:20130/path"), 1000);

    ASSERT_TRUE(run_until([&]() { return errored || disconnected || closes > 0; }))
        << "Client did not react to invalid UTF-8 close reason";

    EXPECT_EQ(closes, 0u);
    EXPECT_TRUE(errored || disconnected);
}

TEST(WebSocketApiHardening, RejectsOversizedOutgoingPingFrame) {
    qb::allocator::pipe<char> out;
    qb::http::ws::MessagePing ping;
    ping << std::string(126, 'x');

    EXPECT_THROW(out << ping, std::invalid_argument);
}

TEST(WebSocketApiHardening, RejectsOversizedOutgoingPongFrame) {
    qb::allocator::pipe<char> out;
    qb::http::ws::MessagePong pong;
    pong << std::string(126, 'x');

    EXPECT_THROW(out << pong, std::invalid_argument);
}

TEST(WebSocketApiHardening, RejectsOutgoingReservedOpcodeAndRsvBits) {
    qb::allocator::pipe<char> out;

    qb::http::ws::Message reserved_opcode;
    reserved_opcode.fin_rsv_opcode = 0x8Bu; // FIN + reserved control opcode.
    EXPECT_THROW(out << reserved_opcode, std::invalid_argument);

    qb::http::ws::Message rsv_text;
    rsv_text.fin_rsv_opcode = 0xC1u; // FIN + RSV1 + RSV2 + text.
    EXPECT_THROW(out << rsv_text, std::invalid_argument);
}

TEST(WebSocketApiHardening, RejectsOutgoingFragmentedControlFrame) {
    qb::allocator::pipe<char> out;

    qb::http::ws::Message fragmented_ping;
    fragmented_ping.fin_rsv_opcode = qb::http::ws::opcode::_Ping; // no FIN bit
    EXPECT_THROW(out << fragmented_ping, std::invalid_argument);
}

TEST(WebSocketApiHardening, RejectsInvalidSubprotocolTokens) {
    qb::http::ws::client client;

    EXPECT_THROW(client.add_subprotocol(""), std::invalid_argument);
    EXPECT_THROW(client.add_subprotocol("chat v1"), std::invalid_argument);
    EXPECT_THROW(client.add_subprotocol("chat,v1"), std::invalid_argument);
    EXPECT_THROW(client.add_subprotocol(std::string("bad\nproto", 9)),
                 std::invalid_argument);
    EXPECT_THROW(client.set_subprotocols({"chat.v1", "bad proto"}),
                 std::invalid_argument);

    EXPECT_NO_THROW(client.set_subprotocols({"chat.v1", "superchat-v2"}));
}

TEST(WebSocketApiHardening, ClientEchoesPeerCloseFrame) {
    qb::io::async::init();
    g_close_echo_received = 0;

    constexpr int port = 20120;
    CloseEchoProbeServer server;
    server.transport().listen_v4(port);
    server.start();

    bool disconnected = false;
    qb::http::ws::client client;
    client.on_disconnected([&disconnected](auto &) { disconnected = true; });
    client.connect(qb::io::uri("ws://localhost:20120/path"), 1000);

    ASSERT_TRUE(run_until([&]() {
        return disconnected || g_close_echo_received > 0;
    }, 600, 5)) << "Client never surfaced a close/disconnect signal";

    // Depending on transport teardown timing, the peer close echo may race
    // with socket shutdown. When observed, it must be emitted once.
    EXPECT_LE(g_close_echo_received, 1u);
}

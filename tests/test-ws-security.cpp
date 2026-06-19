/**
 * @file test-security.cpp
 * @brief WebSocket security testing implementation
 *
 * This test suite provides extensive security testing for the WebSocket protocol:
 * - Validates proper handling of invalid handshakes
 * - Tests rejection of unmasked frames from client to server
 * - Verifies key uniqueness and proper accept key computation
 * - Ensures WebSocket protocol compliance with RFC 6455
 *
 * These tests verify that the WebSocket implementation properly enforces
 * security requirements and protocol rules.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
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

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <gtest/gtest.h>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <qb/io/async.h>
#include <set>
#include <stdexcept>
#include <string_view>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include "../ws/ws.h"

// Utiliser des namespace plus spécifiques pour éviter les ambiguïtés
// using namespace qb::io;
// using namespace qb::http; // Supprimé pour éviter les ambiguïtés

// Global variables for test synchronization
std::atomic<bool>        server_active{false};
std::atomic<std::size_t> connection_count{0};
std::atomic<std::size_t> rejection_count{0};
std::mutex               test_mutex;
std::condition_variable  test_cv;
bool                     test_complete = false;

/**
 * @brief Forward declaration of the security test server
 */
class SecurityServer;

/**
 * @brief Client handler for the security test server
 *
 * Implements validation of WebSocket handshakes and protocol compliance
 * by checking headers, keys, and message masking requirements.
 */
class SecurityServerClient : public qb::io::use<SecurityServerClient>::tcp::client<SecurityServer> {
private:
    bool _validated = false; ///< Flag indicating whether the client handshake was validated

public:
    using Protocol    = qb::http::protocol<SecurityServerClient>;
    using WS_Protocol = qb::http::ws::protocol<SecurityServerClient>;

    /**
     * @brief Construct a new SecurityServerClient
     * @param server Reference to the server
     */
    explicit SecurityServerClient(IOServer &server)
        : qb::io::use<SecurityServerClient>::tcp::client<SecurityServer>(server) {}

    /**
     * @brief Handle incoming HTTP request for WebSocket handshake
     * @param event The HTTP request event
     *
     * Validates the security requirements of the WebSocket protocol:
     * - Checks for valid WebSocket version (13)
     * - Ensures WebSocket key is present
     * - Verifies proper upgrade and connection headers
     */
    void
    on(typename Protocol::request &&request) {
        // Check security headers and requirements
        bool valid = true;

        // Check WebSocket version
        if (request.header("Sec-WebSocket-Version") != "13") {
            valid = false;
        }

        // Check required headers
        if (request.header("Sec-WebSocket-Key").empty()) {
            valid = false;
        }

        // Check for upgrade header
        if (!request.upgrade || request.header("Upgrade") != "websocket" || request.header("Connection").find("Upgrade") == std::string::npos) {
            valid = false;
        }

        // Check for any custom headers or security tokens that might be required
        // (In a real application, you might add more validation here)

        if (valid) {
            _validated = true;
            if (!this->switch_protocol<WS_Protocol>(*this, request)) {
                ++rejection_count;
                disconnect();
            } else {
                ++connection_count;
            }
        } else {
            // Return 400 Bad Request for invalid requests
            qb::http::Response res;
            res.status() = qb::http::status::BAD_REQUEST;
            res.body()   = "Invalid WebSocket request";
            *this << res;
            ++rejection_count;
            disconnect();
        }
    }

    /**
     * @brief Handle WebSocket messages
     * @param event The WebSocket message event
     *
     * Echo back the message only if the client has been validated.
     */
    void
    on(typename WS_Protocol::message &&event) {
        // Echo back the message after validation
        if (_validated) {
            event.ws.masked = false;
            *this << event.ws;
        } else {
            disconnect();
        }
    }

    /**
     * @brief Handle WebSocket close frame
     * @param event The WebSocket close event
     */
    void
    on(typename WS_Protocol::close &&event) {
        disconnect();
    }
};

/**
 * @brief Security test server
 *
 * Manages WebSocket connections and handles test completion tracking.
 */
class SecurityServer : public qb::io::use<SecurityServer>::tcp::server<SecurityServerClient> {
public:
    /**
     * @brief Handle new IO session
     * @param _ The IO session event (unused)
     */
    void
    on(IOSession &) {
        // Client connected
    }

    /**
     * @brief Handle client disconnection
     * @param _ The disconnection event (unused)
     *
     * Tracks active connections and signals test completion when all clients disconnect.
     */
    void
    on(qb::io::async::event::disconnected &) {
        auto current = connection_count.load(std::memory_order_acquire);
        while (current != 0
               && !connection_count.compare_exchange_weak(current, current - 1, std::memory_order_acq_rel, std::memory_order_acquire)) {
        }

        if (current == 1 && server_active) {
            // When all connections are closed, signal test completion
            std::unique_lock<std::mutex> lock(test_mutex);
            test_complete = true;
            test_cv.notify_all();
        }
    }

    /**
     * @brief Start the security test
     *
     * Marks the server as active for test tracking.
     */
    void
    start_test() {
        server_active = true;
    }
};

class SecurityServerThread {
    std::thread       _thread;
    std::atomic<bool> _ready{false};
    std::atomic<bool> _listening{false};
    std::atomic<bool> _running{true};
    int               _port;

public:
    explicit SecurityServerThread(int port)
        : _port(port) {
        server_active    = false;
        connection_count = 0;
        rejection_count  = 0;
        test_complete    = false;

        _thread = std::thread([this] {
            qb::io::async::init();

            SecurityServer server;
            const auto     listen_status = server.transport().listen_v6(_port);
            _listening.store(listen_status == qb::io::SocketStatus::Done, std::memory_order_release);
            _ready.store(true, std::memory_order_release);
            if (listen_status != qb::io::SocketStatus::Done) {
                return;
            }

            server.start();
            server.start_test();
            while (_running.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(2));
                }
            }
        });

        while (!_ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        if (!_listening.load(std::memory_order_acquire)) {
            throw std::runtime_error("Security test server failed to listen");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }

    ~SecurityServerThread() {
        _running.store(false, std::memory_order_release);
        if (_thread.joinable()) {
            _thread.join();
        }
    }
};

class RawSocket {
    int _fd{-1};

public:
    explicit RawSocket(int port) {
        _fd = ::socket(AF_INET6, SOCK_STREAM, 0);
        if (_fd < 0) {
            throw std::runtime_error("socket() failed");
        }

        timeval timeout{};
        timeout.tv_sec = 2;
        ::setsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        ::setsockopt(_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port   = htons(static_cast<std::uint16_t>(port));
        if (::inet_pton(AF_INET6, "::1", &addr.sin6_addr) != 1) {
            ::close(_fd);
            _fd = -1;
            throw std::runtime_error("inet_pton(::1) failed");
        }
        if (::connect(_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
            ::close(_fd);
            _fd = -1;
            throw std::runtime_error("connect(::1) failed");
        }
    }

    RawSocket(RawSocket const &)            = delete;
    RawSocket &operator=(RawSocket const &) = delete;

    ~RawSocket() {
        if (_fd >= 0) {
            ::close(_fd);
        }
    }

    void
    send_all(std::string_view bytes) {
        const char *data = bytes.data();
        auto        left = bytes.size();
        while (left > 0) {
            const auto sent = ::send(_fd, data, left, 0);
            if (sent <= 0) {
                throw std::runtime_error("send() failed");
            }
            data += sent;
            left -= static_cast<std::size_t>(sent);
        }
    }

    std::string
    recv_some(std::size_t max_bytes = 4096) {
        std::string out;
        out.resize(max_bytes);
        const auto n = ::recv(_fd, out.data(), out.size(), 0);
        if (n <= 0) {
            out.clear();
            return out;
        }
        out.resize(static_cast<std::size_t>(n));
        return out;
    }
};

std::string
raw_handshake_request(std::string_view key, std::string_view version = "13", std::string_view method = "GET") {
    std::string request;
    request += method;
    request += " / HTTP/1.1\r\n";
    request += "Host: localhost:20160\r\n";
    request += "Upgrade: websocket\r\n";
    request += "Connection: Upgrade\r\n";
    if (!key.empty()) {
        request += "Sec-WebSocket-Key: ";
        request += key;
        request += "\r\n";
    }
    request += "Sec-WebSocket-Version: ";
    request += version;
    request += "\r\n\r\n";
    return request;
}

std::string
read_http_response(RawSocket &socket) {
    std::string response;
    for (int i = 0; i < 20 && response.find("\r\n\r\n") == std::string::npos; ++i) {
        response += socket.recv_some();
        if (response.find("\r\n\r\n") != std::string::npos) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return response;
}

/**
 * @brief Test valid WebSocket handshake
 *
 * Verifies that a properly formatted WebSocket connection is accepted
 * and handled correctly.
 */
TEST(Security, VALID_HANDSHAKE) {
    SecurityServerThread server{20160};
    RawSocket            socket{20160};

    const auto key = qb::http::ws::generateKey();
    socket.send_all(raw_handshake_request(key));

    const auto response = read_http_response(socket);
    EXPECT_NE(response.find("101"), std::string::npos) << response;
    EXPECT_NE(response.find("sec-websocket-accept"), std::string::npos) << response;
    EXPECT_EQ(rejection_count, 0);
}

/**
 * @brief Test invalid handshake (missing key)
 *
 * Verifies that a WebSocket handshake without the required key
 * is properly rejected.
 */
TEST(Security, INVALID_KEY) {
    SecurityServerThread server{20160};
    RawSocket            socket{20160};

    socket.send_all(raw_handshake_request(""));

    const auto response = read_http_response(socket);
    EXPECT_NE(response.find("400"), std::string::npos) << response;
    EXPECT_EQ(connection_count, 0) << "No WebSocket connection should be established";
    EXPECT_GE(rejection_count, 1) << "Missing key should cause rejection";
}

/**
 * @brief Test invalid WebSocket version
 *
 * Verifies that a WebSocket handshake with an unsupported version
 * is properly rejected.
 */
TEST(Security, INVALID_VERSION) {
    SecurityServerThread server{20160};
    RawSocket            socket{20160};

    socket.send_all(raw_handshake_request(qb::http::ws::generateKey(), "12"));

    const auto response = read_http_response(socket);
    EXPECT_NE(response.find("400"), std::string::npos) << response;
    EXPECT_EQ(connection_count, 0) << "No WebSocket connection should be established";
    EXPECT_GE(rejection_count, 1) << "Invalid WebSocket version should cause rejection";
}

TEST(Security, INVALID_METHOD) {
    SecurityServerThread server{20160};
    RawSocket            socket{20160};

    socket.send_all(raw_handshake_request(qb::http::ws::generateKey(), "13", "POST"));

    const auto response = read_http_response(socket);
    EXPECT_NE(response.find("400"), std::string::npos) << response;
    EXPECT_EQ(connection_count, 0) << "No WebSocket connection should be established";
    EXPECT_GE(rejection_count, 1) << "Non-GET WebSocket handshake must be rejected";
}

/**
 * @brief Test unmasked frames from client
 *
 * Verifies that a WebSocket server properly rejects unmasked frames
 * sent from client to server, as required by RFC 6455.
 */
TEST(Security, UNMASKED_FRAMES) {
    SecurityServerThread server{20160};
    RawSocket            socket{20160};

    socket.send_all(raw_handshake_request(qb::http::ws::generateKey()));
    const auto response = read_http_response(socket);
    ASSERT_NE(response.find("101"), std::string::npos) << response;

    const std::string payload = "unmasked payload";
    std::string       frame;
    frame.push_back(static_cast<char>(0x81));
    frame.push_back(static_cast<char>(payload.size()));
    frame += payload;
    socket.send_all(frame);

    const auto close_frame = socket.recv_some();
    ASSERT_GE(close_frame.size(), 4u);
    EXPECT_EQ(static_cast<unsigned char>(close_frame[0]), 0x88);
    EXPECT_LE(static_cast<unsigned char>(close_frame[1]), 125);
    const auto code = (static_cast<unsigned char>(close_frame[2]) << 8) | static_cast<unsigned char>(close_frame[3]);
    EXPECT_EQ(code, static_cast<int>(qb::http::ws::CloseStatus::ProtocolError));
}

/**
 * @brief Test that keys are properly unique and random
 *
 * Verifies that the WebSocket key generation produces unique keys
 * as required for security purposes.
 */
TEST(Security, KEY_UNIQUENESS) {
    std::set<std::string> keys;
    const int             NUM_KEYS = 100;

    for (int i = 0; i < NUM_KEYS; ++i) {
        std::string key = qb::http::ws::generateKey();
        EXPECT_FALSE(keys.count(key)) << "Key collision detected";
        keys.insert(key);
    }

    EXPECT_EQ(keys.size(), NUM_KEYS) << "Keys should be unique";
}

/**
 * @brief Test that the WebSocket accept key computation is correct
 *
 * Verifies that the server computes the accept key according to the
 * WebSocket specification (RFC 6455) by checking against a known example.
 */
TEST(Security, ACCEPT_KEY_COMPUTATION) {
    std::string key             = "dGhlIHNhbXBsZSBub25jZQ==";
    std::string expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    std::string magic           = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string computed_accept = qb::crypto::base64::encode(qb::crypto::sha1(key + magic));

    EXPECT_EQ(computed_accept, expected_accept) << "Accept key computation is incorrect";
}

/**
 * @brief Main function for the test executable
 *
 * @param argc Command line argument count
 * @param argv Command line arguments
 * @return int Exit code
 */
int
main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

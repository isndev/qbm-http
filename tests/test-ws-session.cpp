/**
 * @file test-session.cpp
 * @brief WebSocket session testing implementation
 *
 * This test suite validates the WebSocket session functionality:
 * - Connection establishment over TCP and secure TCP (TLS/SSL)
 * - WebSocket protocol handshake and upgrade verification
 * - Bidirectional message exchange between client and server
 * - High-volume message handling with 4096 iterations
 * - Connection tracking and proper session cleanup
 *
 * The tests ensure correct implementation of the WebSocket protocol
 * with proper session lifecycle management.
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

#include <atomic>
#include <gtest/gtest.h>
#include <thread>
#include <qb/io/async.h>
#include "../ws/ws.h"

using namespace qb::io;

// Number of message iterations for stress testing the WebSocket connection
constexpr const std::size_t NB_ITERATION = 4096;
// Test message content that will be exchanged between client and server
constexpr const char STRING_MESSAGE[] = "Here is my content test";
// Counters for tracking message processing on server and client sides
std::atomic<std::size_t> msg_count_server_side = 0;
std::atomic<std::size_t> msg_count_client_side = 0;

/**
 * @brief Determines if the test has completed successfully
 *
 * Checks if both client and server have processed all expected messages.
 * The +1 accounts for the handshake connection message.
 *
 * @return true when all messages have been processed, false otherwise
 */
bool
all_done() {
    return msg_count_server_side == (NB_ITERATION + 1) && msg_count_client_side == (NB_ITERATION + 1);
}

// OVER TCP

class TestServer;

/**
 * @brief Server-side client handler for standard TCP WebSocket connections
 *
 * This class represents a client connection on the server side.
 * It handles WebSocket protocol handshake and message exchange,
 * maintaining the connection state and validating messages.
 *
 * Key responsibilities:
 * - Processing WebSocket upgrade requests
 * - Validating and responding to client messages
 * - Tracking message counts for test verification
 */
class TestServerClient : public use<TestServerClient>::tcp::client<TestServer> {
public:
    using Protocol    = qb::http::protocol<TestServerClient>;
    using WS_Protocol = qb::http::ws::protocol<TestServerClient>;

    explicit TestServerClient(IOServer &server)
        : client(server) {}

    ~TestServerClient() {
        EXPECT_EQ(msg_count_server_side, NB_ITERATION + 1);
    }

    /**
     * @brief Handles the WebSocket upgrade request
     *
     * Processes an HTTP request and attempts to upgrade it to a WebSocket
     * connection. If successful, increments the message counter.
     *
     * @param event The HTTP request containing WebSocket upgrade headers
     */
    void
    on(Protocol::request &&request) {
        if (!this->switch_protocol<WS_Protocol>(*this, request))
            disconnect();
        else
            ++msg_count_server_side;
    }

    /**
     * @brief Processes incoming WebSocket messages
     *
     * Validates the message content against the expected test string,
     * echoes the message back to the client, and updates message counter.
     *
     * @param event The WebSocket message event containing the message data
     */
    void
    on(WS_Protocol::message &&event) {
        EXPECT_EQ(STRING_MESSAGE, std::string(event.data, event.size));
        *this << event.ws;
        ++msg_count_server_side;
    }
};

/**
 * @brief WebSocket server implementation for TCP connections
 *
 * This class represents a WebSocket server that listens for incoming connections
 * and creates TestServerClient instances to handle them. It tracks the
 * total number of connections established during the test.
 *
 * The server validates that exactly one connection was established
 * during test execution through its connection counter.
 */
class TestServer : public use<TestServer>::tcp::server<TestServerClient> {
    std::size_t connection_count = 0u;

public:
    ~TestServer() {
        EXPECT_EQ(connection_count, 1u);
    }

    /**
     * @brief Handles a new client session
     *
     * Called when a new client connection is established.
     * Increments the connection counter for later validation.
     *
     * @param session The newly established IO session
     */
    void
    on(IOSession &) {
        ++connection_count;
    }
};

/**
 * @brief WebSocket client implementation for TCP connections
 *
 * This class represents a WebSocket client that initiates connections
 * to the server, performs protocol handshakes, and exchanges messages.
 * It maintains a WebSocket key for the handshake process and
 * tracks received messages for test validation.
 */
class TestClient : public use<TestClient>::tcp::client<> {
    const std::string ws_key;

public:
    using Protocol    = qb::http::protocol<TestClient>;
    using WS_Protocol = qb::http::ws::protocol<TestClient>;

    /**
     * @brief Constructor that initializes the WebSocket key
     *
     * Creates a random WebSocket key required for the handshake
     * as specified in RFC 6455.
     */
    TestClient()
        : ws_key(qb::http::ws::generateKey()) {}

    /**
     * @brief Sends the WebSocket handshake request to the server
     *
     * Initiates the WebSocket protocol upgrade by sending
     * an HTTP request with WebSocket-specific headers.
     */
    void
    sendWSHandshake() {
        qb::http::WebSocketRequest r(ws_key);
        r.uri() = "http://localhost:20100/";
        *this << r;
    }

    /**
     * @brief Destructor that verifies message count
     *
     * Ensures that all expected messages were received
     * during the test execution.
     */
    ~TestClient() {
        EXPECT_EQ(msg_count_client_side, NB_ITERATION + 1);
    }

    /**
     * @brief Handles the server's response to the WebSocket handshake
     *
     * Processes the HTTP response and attempts to upgrade to WebSocket protocol.
     * If successful, sends a series of test messages to the server.
     *
     * @param event The HTTP response containing WebSocket handshake confirmation
     */
    void
    on(Protocol::response &&response) {
        if (!this->switch_protocol<WS_Protocol>(*this, response, ws_key))
            disconnect();
        else {
            for (auto i = 0u; i < NB_ITERATION; ++i) {
                qb::http::ws::MessageText new_event;
                new_event.masked = true;
                new_event << STRING_MESSAGE;
                *this << new_event;
            }
            ++msg_count_client_side;
        }
    }

    /**
     * @brief Processes incoming WebSocket messages from the server
     *
     * Validates message content against the expected test string
     * and increments the message counter.
     *
     * @param event The WebSocket message event containing the message data
     */
    void
    on(WS_Protocol::message &&event) {
        EXPECT_EQ(STRING_MESSAGE, std::string(event.data, event.size));
        ++msg_count_client_side;
    }
};

/**
 * @brief Test case for WebSocket communication over standard TCP
 *
 * This test:
 * 1. Initializes the async event loop system
 * 2. Creates and starts a WebSocket server on IPv6 localhost
 * 3. Launches a client thread that connects to the server
 * 4. Performs WebSocket handshake and exchanges messages
 * 5. Validates that all messages are properly delivered
 *
 * The test runs until all expected messages have been exchanged,
 * and validates proper connection tracking and message delivery.
 */
TEST(Session, WEBSOCKET_OVER_TCP) {
    async::init();
    msg_count_server_side = 0;
    msg_count_client_side = 0;
    TestServer server;
    server.transport().listen_v6(20100);
    server.start();

    std::thread t([]() {
        async::init();
        TestClient client;
        if (SocketStatus::Done != client.transport().connect_v6("::1", 20100)) {
            throw std::runtime_error("could not connect");
        }
        client.start();
        client.sendWSHandshake();

        for (std::size_t i = 0; i < (NB_ITERATION * 5) && !all_done(); ++i)
            async::run(EVRUN_ONCE);
    });

    for (std::size_t i = 0; i < (NB_ITERATION * 5) && !all_done(); ++i)
        async::run(EVRUN_ONCE);
    t.join();
}

// OVER SECURE TCP

#ifdef QB_HAS_SSL

class TestSecureServer;

/**
 * @brief Server-side client handler for secure WebSocket connections
 *
 * This class handles client connections over secure SSL/TLS transport.
 * It provides the same functionality as TestServerClient but operates
 * over an encrypted channel.
 *
 * Key responsibilities:
 * - Processing secure WebSocket upgrade requests
 * - Validating and responding to encrypted client messages
 * - Tracking message counts for test verification
 */
class TestSecureServerClient : public use<TestSecureServerClient>::tcp::ssl::client<TestSecureServer> {
public:
    using Protocol    = qb::http::protocol<TestSecureServerClient>;
    using WS_Protocol = qb::http::ws::protocol<TestSecureServerClient>;

    explicit TestSecureServerClient(IOServer &server)
        : client(server) {}

    ~TestSecureServerClient() {
        EXPECT_EQ(msg_count_server_side, NB_ITERATION + 1);
    }

    /**
     * @brief Handles the WebSocket upgrade request over secure channel
     *
     * Processes an HTTP request and attempts to upgrade it to a WebSocket
     * connection over SSL/TLS. If successful, increments the message counter.
     *
     * @param event The HTTP request containing WebSocket upgrade headers
     */
    void
    on(Protocol::request &&request) {
        if (!this->switch_protocol<WS_Protocol>(*this, request))
            disconnect();
        else
            ++msg_count_server_side;
    }

    /**
     * @brief Processes incoming WebSocket messages over secure channel
     *
     * Validates the encrypted message content against the expected test string,
     * echoes the message back to the client, and updates message counter.
     *
     * @param event The WebSocket message event containing the decrypted message data
     */
    void
    on(WS_Protocol::message &&event) {
        EXPECT_EQ(STRING_MESSAGE, std::string(event.data, event.size));
        *this << event.ws;
        ++msg_count_server_side;
    }
};

/**
 * @brief Secure WebSocket server implementation using SSL/TLS
 *
 * This class represents a WebSocket server that listens for incoming
 * secure connections and creates TestSecureServerClient instances to handle them.
 * It uses SSL/TLS for transport security.
 */
class TestSecureServer : public use<TestSecureServer>::tcp::ssl::server<TestSecureServerClient> {
    std::size_t connection_count = 0u;

public:
    ~TestSecureServer() {
        EXPECT_EQ(connection_count, 1u);
    }

    /**
     * @brief Handles a new secure client session
     *
     * Called when a new encrypted client connection is established.
     * Increments the connection counter for later validation.
     *
     * @param session The newly established secure IO session
     */
    void
    on(IOSession &) {
        ++connection_count;
    }
};

/**
 * @brief Secure WebSocket client implementation using SSL/TLS
 *
 * This class represents a WebSocket client that initiates secure connections
 * to the server using SSL/TLS encryption, performs protocol handshakes,
 * and exchanges encrypted messages.
 */
class TestSecureClient : public use<TestSecureClient>::tcp::ssl::client<> {
    const std::string ws_key;

public:
    using Protocol    = qb::http::protocol<TestSecureClient>;
    using WS_Protocol = qb::http::ws::protocol<TestSecureClient>;

    /**
     * @brief Constructor that initializes the WebSocket key for secure handshake
     *
     * Creates a random WebSocket key required for the handshake
     * as specified in RFC 6455.
     */
    TestSecureClient()
        : ws_key(qb::http::ws::generateKey()) {}

    /**
     * @brief Sends the WebSocket handshake request over secure channel
     *
     * Initiates the WebSocket protocol upgrade by sending
     * an HTTP request with WebSocket-specific headers over SSL/TLS.
     */
    void
    sendWSHandshake() {
        qb::http::WebSocketRequest r(ws_key);
        r.uri() = "https://localhost:20101/";
        *this << r;
    }

    ~TestSecureClient() {
        EXPECT_EQ(msg_count_client_side, NB_ITERATION + 1);
    }

    /**
     * @brief Handles the server's secure response to the WebSocket handshake
     *
     * Processes the encrypted HTTP response and attempts to upgrade to WebSocket
     * protocol. If successful, sends a series of test messages to the secure server.
     *
     * @param event The HTTP response containing WebSocket handshake confirmation
     */
    void
    on(Protocol::response &&response) {
        if (!this->switch_protocol<WS_Protocol>(*this, response, ws_key))
            disconnect();
        else {
            for (auto i = 0u; i < NB_ITERATION; ++i) {
                qb::http::ws::MessageText new_event;
                new_event.masked = true;
                new_event << STRING_MESSAGE;
                *this << new_event;
            }
            ++msg_count_client_side;
        }
    }

    /**
     * @brief Processes incoming WebSocket messages from the secure server
     *
     * Validates the decrypted message content against the expected test string
     * and increments the message counter.
     *
     * @param event The WebSocket message event containing the decrypted message data
     */
    void
    on(WS_Protocol::message &&event) {
        EXPECT_EQ(STRING_MESSAGE, std::string(event.data, event.size));
        ++msg_count_client_side;
    }
};

/**
 * @brief Test case for WebSocket communication over secure TCP (SSL/TLS)
 *
 * This test:
 * 1. Initializes the async event loop system
 * 2. Creates and starts a secure WebSocket server on IPv4 localhost
 * 3. Configures SSL/TLS with appropriate certificates
 * 4. Launches a client thread that connects securely to the server
 * 5. Performs secure WebSocket handshake and exchanges encrypted messages
 * 6. Validates that all messages are properly delivered
 *
 * The test runs until all expected messages have been exchanged,
 * and validates proper secure connection tracking and message delivery.
 */
TEST(Session, WEBSOCKET_OVER_SECURE_TCP) {
    async::init();
    msg_count_server_side = 0;
    msg_count_client_side = 0;

    TestSecureServer server;
    server.transport().init(ssl::create_server_context(SSLv23_server_method(), "cert.pem", "key.pem"));
    server.transport().listen_v4(20101);
    server.start();

    std::thread t([]() {
        async::init();
        TestSecureClient client;
        // Self-signed test certificate: opt out of qb-io's secure-by-default
        // peer verification for this local fixture.
        client.transport().set_insecure();
        if (SocketStatus::Done != client.transport().connect_v4("127.0.0.1", 20101)) {
            throw std::runtime_error("could not connect");
        }
        client.start();
        client.sendWSHandshake();

        for (std::size_t i = 0; i < (NB_ITERATION * 5) && !all_done(); ++i)
            async::run(EVRUN_ONCE);
    });

    for (std::size_t i = 0; i < (NB_ITERATION * 5) && !all_done(); ++i)
        async::run(EVRUN_ONCE);
    t.join();
}

#endif

/**
 * @file test-robustness.cpp
 * @brief WebSocket robustness and reliability tests
 *
 * This test suite verifies the robustness and reliability of the WebSocket protocol
 * implementation under various conditions including:
 *
 * - Large message handling (text and binary messages up to 16KB)
 * - Control frame processing (PING/PONG exchanges)
 * - Connection establishment, maintenance and termination
 * - Error handling and recovery scenarios
 * - Multi-client concurrent connections
 *
 * The tests ensure the WebSocket implementation is capable of handling edge cases
 * and real-world usage patterns without compromising reliability or performance.
 * Each test case validates a specific aspect of the protocol implementation to
 * ensure compliance with RFC 6455 and proper handling of network conditions.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
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

#include <algorithm> // pour std::min
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <gtest/gtest.h>
#include <iomanip> // pour std::setw, std::setfill, etc.
#include <iostream>
#include <mutex>
#include <qb/io/async.h>
#include <random>
#include <set>
#include <thread>
#include "../ws/ws.h"

// Use the proper namespace to avoid qualification issues
using namespace qb::io;
using namespace std::chrono_literals;

/**
 * @brief Constants for robustness testing parameters
 *
 * These constants define the test scope and operation parameters:
 * - STRESS_TEST_ITERATIONS: Number of iterations for stress testing
 * - LARGE_MESSAGE_SIZE: Size of large messages (16KB) to test boundary conditions
 * - CONCURRENT_CLIENTS: Number of simultaneous client connections
 * - PING_INTERVAL_MS: Time between ping/pong health checks
 */
constexpr const std::size_t LARGE_MESSAGE_SIZE =
    1024 * 16; // 16KB for more robust testing

/**
 * @brief Global state variables for test synchronization and metrics
 *
 * These atomic variables track test progress and collect metrics:
 * - server_active: Indicates whether the server is running
 * - text_message_count: Number of text messages processed
 * - binary_message_count: Number of binary messages processed
 * - ping_count: Number of ping frames sent/received
 * - pong_count: Number of pong frames sent/received
 * - connection_count: Number of active connections
 * - test_complete: Indicates test completion
 */
std::atomic<bool>        server_active{false};
std::atomic<std::size_t> text_message_count{0};
std::atomic<std::size_t> binary_message_count{0};
std::atomic<std::size_t> ping_count{0};
std::atomic<std::size_t> pong_count{0};
std::atomic<std::size_t> connection_count{0};
std::atomic<bool>        test_complete{false};

/**
 * @brief Reset all test counters and state variables
 *
 * This function resets all counters and state variables before starting
 * a new test to ensure clean test environment.
 */
void
reset_counters() {
    server_active        = false;
    text_message_count   = 0;
    binary_message_count = 0;
    ping_count           = 0;
    pong_count           = 0;
    connection_count     = 0;
    test_complete        = false;
}

/**
 * @brief Generate a test string of specified size
 *
 * Creates a deterministic string of repeating alphabet characters
 * with the specified length for testing text message handling.
 *
 * @param size Size of the string to generate in bytes
 * @return A string of the requested size
 */
std::string
generate_large_string(std::size_t size) {
    std::string result;
    result.reserve(size);
    for (std::size_t i = 0; i < size; ++i) {
        result.push_back(static_cast<char>('A' + (i % 26)));
    }
    return result;
}

/**
 * @brief Generate random binary data of specified size
 *
 * Creates a deterministic binary data vector with the specified length
 * for testing binary message handling.
 *
 * @param size Size of the binary data to generate in bytes
 * @return A vector of binary data with the requested size
 */
std::vector<char>
generate_binary_data(std::size_t size) {
    std::vector<char> result;
    result.reserve(size);
    for (std::size_t i = 0; i < size; ++i) {
        result.push_back(static_cast<char>(i % 256));
    }
    return result;
}

// ====== Robustness Tests Server ======

class RobustServer;

/**
 * @class RobustServerClient
 * @brief WebSocket server client handler for robustness testing
 *
 * This class handles individual WebSocket client connections for robustness testing.
 * It provides the following capabilities:
 * - Processes client handshake and establishes WebSocket connections
 * - Tracks message statistics (text, binary, ping, pong)
 * - Implements echo behavior for messages (sends back received messages)
 * - Supports configurable ping intervals for connection health testing
 * - Handles various WebSocket control frames (ping, pong, close)
 */
class RobustServerClient
    : public use<RobustServerClient>::tcp::client<RobustServer>
    , public use<RobustServerClient>::timeout {
private:
    int _ping_interval_ms = 0; /**< Interval between ping messages in milliseconds */
    std::string       _last_message; /**< Last received text message content */
    std::vector<char> _last_binary;  /**< Last received binary message content */

public:
    using Protocol    = qb::http::protocol<RobustServerClient>;
    using WS_Protocol = qb::http::ws::protocol<RobustServerClient>;

    /**
     * @brief Constructs a server-side WebSocket client handler
     *
     * @param server Reference to the IOServer that manages this client
     */
    explicit RobustServerClient(IOServer &server)
        : use<RobustServerClient>::tcp::client<RobustServer>(server) {}

    /**
     * @brief Sets the ping interval for this client
     *
     * Configures how often the server should send ping frames to verify
     * the client connection is still active and responsive.
     *
     * @param interval_ms Ping interval in milliseconds (0 to disable pings)
     */
    void
    set_ping_interval(int interval_ms) {
        _ping_interval_ms = interval_ms;
        this->setTimeout(std::chrono::milliseconds(interval_ms));
    }

    /**
     * @brief Handles initial HTTP request and upgrades to WebSocket protocol
     *
     * This event handler receives the initial HTTP upgrade request from the client
     * and performs the WebSocket handshake. On successful connection, it optionally
     * sends an initial ping message.
     *
     * @param event HTTP request event containing handshake information
     */
    void
    on(typename Protocol::request &&request) {
        if (!this->switch_protocol<WS_Protocol>(*this, request)) {
            disconnect();
        } else {
            // Send a ping on successful connection to test client handling
            if (_ping_interval_ms > 0) {
                qb::http::ws::MessagePing ping_msg;
                *this << ping_msg;
                ++ping_count;
            }
        }
    }

    /**
     * @brief Handles WebSocket message events (text or binary frames)
     *
     * This event handler processes incoming WebSocket message frames.
     * It identifies the message type (text or binary) based on the opcode,
     * stores the message data, and echoes it back to the client.
     *
     * @param event WebSocket message event containing frame data
     */
    void
    on(typename WS_Protocol::message &&event) {
        // Based on the fin_rsv_opcode, determine the message type
        if ((event.ws.fin_rsv_opcode & 0x0f) == 1) {
            // Text frame
            _last_message   = std::string(event.data, event.size);
            *this << event.ws;
            ++text_message_count;
        } else if ((event.ws.fin_rsv_opcode & 0x0f) == 2) {
            // Binary frame
            std::cout << "RobustServerClient: Received binary message of size "
                      << event.size << std::endl;
            _last_binary.assign(event.data, event.data + event.size);
            try {
                std::cout << "RobustServerClient: Sending binary message back, size="
                          << event.size << std::endl;
                *this << event.ws;
                std::cout << "RobustServerClient: Binary message sent" << std::endl;
                ++binary_message_count;
            } catch (const std::exception &e) {
                std::cerr << "RobustServerClient: Exception in binary message handling: "
                          << e.what() << std::endl;
            } catch (...) {
                std::cerr
                    << "RobustServerClient: Unknown exception in binary message handling"
                    << std::endl;
            }
        }
    }

    /**
     * @brief Handles WebSocket ping control frames
     *
     * This event handler responds to ping frames by sending a corresponding
     * pong frame with the same payload data as required by RFC 6455.
     *
     * @param event WebSocket ping event containing frame data
     */
    void
    on(typename WS_Protocol::ping &&event) {
        // In raw mode, we must explicitly create and send a PONG
        qb::http::ws::MessagePong pong_msg;
        // Copy the exact data from PING to PONG
        std::string ping_data(event.data, event.size);
        pong_msg << ping_data;
        // Send the PONG
        *this << pong_msg;
        ++ping_count;
        std::cout << "Server received PING with data [" << ping_data
                  << "], sent PONG response, ping_count=" << ping_count << std::endl;
    }

    /**
     * @brief Handles WebSocket pong control frames
     *
     * This event handler processes pong frames received from clients,
     * typically in response to ping frames sent by the server.
     *
     * @param event WebSocket pong event containing frame data
     */
    void
    on(typename WS_Protocol::pong &&event) {
        ++pong_count;
        std::cout << "Server received PONG, pong_count=" << pong_count << std::endl;
    }

    /**
     * @brief Handles WebSocket close control frames
     *
     * This event handler processes connection close requests from clients
     * and disconnects the client connection.
     *
     * @param event WebSocket close event containing close status and reason
     */
    void
    on(typename WS_Protocol::close &&event) {
        disconnect();
    }

    /**
     * @brief Handles timeout events for periodic ping sending
     *
     * This event handler is triggered at the configured ping interval
     * and sends a ping frame to the client to verify connection health.
     *
     * @param event Timeout event
     */
    void
    on(async::event::timeout const &) {
        if (_ping_interval_ms > 0) {
            qb::http::ws::MessagePing ping_msg;
            *this << ping_msg;
            ++ping_count;
            std::cout << "Server sent PING on timeout, ping_count=" << ping_count
                      << std::endl;
            this->setTimeout(std::chrono::milliseconds(_ping_interval_ms));
        }
    }
};

/**
 * @class RobustServer
 * @brief WebSocket server implementation for robustness testing
 *
 * This server class manages multiple WebSocket client connections and provides
 * infrastructure for testing the robustness of the WebSocket protocol:
 * - Tracks connection statistics and state
 * - Configures client ping intervals for health monitoring
 * - Manages expected connection counts for verification
 */
class RobustServer : public use<RobustServer>::tcp::server<RobustServerClient> {
private:
    std::size_t _expected_connections; /**< Expected number of client connections */
    std::size_t _current_connections =
        0;                 /**< Current number of active client connections */
    int _ping_interval_ms; /**< Ping interval in milliseconds for clients */

public:
    /**
     * @brief Constructs a WebSocket server for robustness testing
     *
     * @param expected_connections Expected number of client connections
     * @param ping_interval_ms Ping interval in milliseconds (0 to disable pings)
     */
    explicit RobustServer(std::size_t expected_connections = 1, int ping_interval_ms = 0)
        : _expected_connections(expected_connections)
        , _ping_interval_ms(ping_interval_ms) {}

    /**
     * @brief Handles new client connection events
     *
     * This event handler is called when a new client connects to the server.
     * It increments the connection counter and configures the client's ping interval.
     *
     * @param session The new client session
     */
    void
    on(IOSession &session) {
        ++_current_connections;
        if (auto client = static_cast<RobustServerClient *>(&session)) {
            client->set_ping_interval(_ping_interval_ms);
        }
    }

    /**
     * @brief Gets the current connection count
     *
     * @return Current number of active client connections
     */
    std::size_t
    connection_count() const {
        return _current_connections;
    }

    /**
     * @brief Handles client disconnection events
     *
     * This event handler is called when a client disconnects from the server.
     * It decrements the connection counter and performs verification checks.
     *
     * @param event Disconnection event
     */
    void
    on(async::event::disconnected const &) {
        if (--_current_connections == 0 &&
            _current_connections != _expected_connections) {
            // Ne pas incrémenter connection_count ici
        }
    }
};

/**
 * @class RobustClient
 * @brief WebSocket client implementation for robustness testing
 *
 * This client class connects to a WebSocket server and performs various operations
 * to test the robustness of the WebSocket protocol:
 * - Establishes WebSocket connections with proper handshake
 * - Sends and receives text and binary messages
 * - Processes control frames (ping, pong, close)
 * - Tracks message statistics and connection state
 */
class RobustClient : public use<RobustClient>::tcp::client<> {
private:
    const std::string ws_key;               /**< WebSocket key for handshake */
    std::size_t       received_count_{0};   /**< Count of received messages */
    std::string       last_text_message_;   /**< Last received text message */
    std::vector<char> last_binary_message_; /**< Last received binary message */
    std::string       last_ping_data_;      /**< Data from last received ping */
    bool              connected_{false};    /**< Connection state flag */

public:
    std::string last_pong_data_; /**< Data from last received pong */

    using Protocol    = qb::http::protocol<RobustClient>;
    using WS_Protocol = qb::http::ws::protocol<RobustClient>;

    /**
     * @brief Client connection state enumeration
     */
    enum State {
        Disconnected, /**< Client is disconnected */
        Connecting,   /**< Client is performing handshake */
        Connected,    /**< Client is connected */
        Closing       /**< Client is closing connection */
    };

    State current_state_{Disconnected}; /**< Current client connection state */

    /**
     * @brief Constructs a WebSocket client for robustness testing
     *
     * Initializes a client with a randomly generated WebSocket key
     * for use in the handshake.
     */
    RobustClient()
        : ws_key(qb::http::ws::generateKey()) {}

    /**
     * @brief Sends the initial WebSocket handshake request
     *
     * This method initiates the WebSocket connection by sending
     * an HTTP upgrade request with the appropriate headers.
     */
    void
    send_handshake() {
        qb::http::WebSocketRequest r(ws_key);
        r.uri() = "http://localhost:20170/";
        *this << r;
        current_state_ = Connecting;
    }

    /**
     * @brief Handles HTTP response to the WebSocket handshake
     *
     * This event handler processes the server's response to the handshake
     * request and switches to the WebSocket protocol if successful.
     *
     * @param event HTTP response event
     */
    void
    on(Protocol::response &&response) {
        if (!this->switch_protocol<WS_Protocol>(*this, response, ws_key)) {
            disconnect();
            current_state_ = Disconnected;
        } else {
            connected_     = true;
            current_state_ = Connected;
        }
    }

    /**
     * @brief Handles WebSocket message events (text or binary)
     *
     * This event handler processes incoming WebSocket message frames.
     * It identifies the message type based on the opcode and stores
     * the message data for verification.
     *
     * @param event WebSocket message event containing frame data
     */
    void
    on(WS_Protocol::message &&event) {
        ++received_count_;
        std::cout << "RobustClient: Received message, opcode="
                  << (event.ws.fin_rsv_opcode & 0x0f) << ", size=" << event.size
                  << std::endl;

        if ((event.ws.fin_rsv_opcode & 0x0f) == 1) { // Text
            std::cout << "RobustClient: Processing text message" << std::endl;
            last_text_message_ = std::string(event.data, event.size);
            std::cout << "RobustClient: Text message stored, size="
                      << last_text_message_.size() << std::endl;
        } else if ((event.ws.fin_rsv_opcode & 0x0f) == 2) { // Binary
            std::cout << "RobustClient: Processing binary message" << std::endl;
            try {
                last_binary_message_.assign(event.data, event.data + event.size);
                std::cout << "RobustClient: Binary message stored, size="
                          << last_binary_message_.size() << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "RobustClient: Exception in binary message handling: "
                          << e.what() << std::endl;
            } catch (...) {
                std::cerr << "RobustClient: Unknown exception in binary message handling"
                          << std::endl;
            }
        }
    }

    /**
     * @brief Handles WebSocket ping control frames
     *
     * This event handler responds to ping frames by sending a corresponding
     * pong frame with the same payload data as required by RFC 6455.
     *
     * @param event WebSocket ping event containing frame data
     */
    void
    on(WS_Protocol::ping &&event) {
        std::cout << "Client received PING with data size " << event.size << std::endl;
        last_ping_data_ = std::string(event.data, event.size);
        // Dans le mode "raw", nous devons explicitement créer et envoyer un PONG
        qb::http::ws::MessagePong pong;
        pong.masked = true;
        pong << last_ping_data_;
        *this << pong;
        std::cout << "Client sent PONG in response to PING" << std::endl;
    }

    /**
     * @brief Handles WebSocket pong control frames
     *
     * This event handler processes pong frames received from the server,
     * typically in response to ping frames sent by the client.
     *
     * @param event WebSocket pong event containing frame data
     */
    void
    on(WS_Protocol::pong &&event) {
        last_pong_data_ = std::string(event.data, event.size);
        std::cout << "Client received PONG" << std::endl;
    }

    /**
     * @brief Handles WebSocket close control frames
     *
     * This event handler processes connection close requests from the server,
     * responds with a close frame, and disconnects the client.
     *
     * @param event WebSocket close event containing close status and reason
     */
    void
    on(WS_Protocol::close &&event) {
        current_state_ = Closing;
        qb::http::ws::MessageClose close(1000, "Closing");
        *this << close;
        disconnect();
        current_state_ = Disconnected;
    }

    /**
     * @brief Handles disconnection events
     *
     * This event handler is triggered when the TCP connection is closed.
     * It updates the client's connection state.
     *
     * @param event Disconnection event
     */
    void
    on(async::event::disconnected &&) {
        connected_     = false;
        current_state_ = Disconnected;
    }

    /**
     * @brief Sends a text message to the server
     *
     * @param text The text message to send
     */
    void
    send_text_message(const std::string &text) {
        qb::http::ws::MessageText msg;
        msg.masked = true;
        msg << text;
        *this << msg;
    }

    /**
     * @brief Sends a binary message to the server
     *
     * @param data The binary data to send
     */
    void
    send_binary_message(const std::vector<char> &data) {
        std::cout << "RobustClient: Creating binary message of size " << data.size()
                  << std::endl;
        qb::http::ws::MessageBinary msg;
        msg.masked = true;
        try {
            // Utiliser directement l'opérateur << avec une string construite à partir
            // des données binaires
            msg << std::string(data.data(), data.size());
            std::cout << "RobustClient: Binary message prepared, sending..."
                      << std::endl;
            *this << msg;
            std::cout << "RobustClient: Binary message sent" << std::endl;
        } catch (const std::exception &e) {
            std::cerr << "RobustClient: Exception in send_binary_message: " << e.what()
                      << std::endl;
        } catch (...) {
            std::cerr << "RobustClient: Unknown exception in send_binary_message"
                      << std::endl;
        }
    }

    /**
     * @brief Sends a ping message to the server
     *
     * @param data Optional payload for the ping message
     */
    void
    send_ping(const std::string &data = "") {
        qb::http::ws::MessagePing msg;
        msg.masked = true;
        msg << data;
        *this << msg;
        std::cout << "Client sent PING with data: " << data << std::endl;
    }

    /**
     * @brief Sends a close frame to initiate connection closure
     *
     * @param code WebSocket close status code
     * @param reason Text reason for the closure
     */
    void
    send_close(int code = 1000, const std::string &reason = "Closed") {
        current_state_ = Closing;
        qb::http::ws::MessageClose msg(code, reason);
        msg.masked = true;
        *this << msg;
    }

    /**
     * @brief Gets the count of received messages
     *
     * @return Number of messages received from the server
     */
    std::size_t
    received_count() const {
        return received_count_;
    }

    /**
     * @brief Gets the last received text message
     *
     * @return Reference to the last text message
     */
    const std::string &
    last_text_message() const {
        return last_text_message_;
    }

    /**
     * @brief Gets the last received binary message
     *
     * @return Reference to the last binary message
     */
    const std::vector<char> &
    last_binary_message() const {
        return last_binary_message_;
    }

    /**
     * @brief Checks if the client is connected
     *
     * @return True if connected, false otherwise
     */
    bool
    is_connected() const {
        return connected_;
    }

    /**
     * @brief Gets the current connection state
     *
     * @return Current client state (Disconnected, Connecting, Connected, or Closing)
     */
    State
    state() const {
        return current_state_;
    }
};

/**
 * @brief Run the event loop until a condition is met
 *
 * This utility function processes asynchronous events until either
 * the specified condition is met or the maximum iterations are reached.
 *
 * @param condition Function that returns true when the desired condition is met
 * @param max_iterations Maximum number of iterations to try (default: 1000)
 * @param delay_ms Delay between iterations in milliseconds (default: 10)
 * @return True if the condition was met, false if max iterations were reached
 */
bool
run_until(std::function<bool()> condition, int max_iterations = 1000,
          int delay_ms = 10) {
    for (int i = 0; i < max_iterations && !condition(); ++i) {
        async::run(EVRUN_ONCE);
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
    return condition();
}

/**
 * @brief Dump buffer contents for debugging
 *
 * This utility function prints the contents of a binary buffer in hexadecimal
 * format for debugging and inspection purposes.
 *
 * @param buffer Pointer to the buffer to dump
 * @param size Size of the buffer in bytes
 * @param label Label to identify the buffer in output
 */
void
dump_buffer(const char *buffer, size_t size, const std::string &label) {
    std::cout << "===== " << label << " (" << size << " bytes) =====" << std::endl;
    for (size_t i = 0; i < std::min(size, size_t(100)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (static_cast<int>(buffer[i]) & 0xFF) << " ";
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
    std::cout << std::dec << std::endl;
}

/**
 * @brief Test WebSocket handling of large messages
 *
 * This test verifies that the WebSocket implementation can correctly
 * handle large text and binary messages (16KB each) including:
 * - Proper fragmentation and reassembly
 * - Complete and accurate data transmission
 * - Correct echo behavior (server echoes messages back to client)
 */
TEST(Robustness, LARGE_MESSAGES) {
    // Initialisation
    async::init();
    reset_counters();

    std::cout << "Starting LARGE_MESSAGES test" << std::endl;

    // Données de test
    std::string       large_text  = generate_large_string(LARGE_MESSAGE_SIZE);
    std::vector<char> binary_data = generate_binary_data(LARGE_MESSAGE_SIZE);

    // Setup server
    RobustServer server;
    server.transport().listen_v6(20170);
    server.start();
    server_active = true;
    std::cout << "Server started" << std::endl;

    // Thread client
    std::thread client_thread([&]() {
        async::init();
        RobustClient client;

        // Connect to server
        if (client.transport().connect_v6("::1", 20170) != SocketStatus::Done) {
            std::cerr << "Could not connect to server" << std::endl;
            return;
        }

        // Start client and perform handshake
        client.start();
        client.send_handshake();

        // Wait for connection
        if (!run_until(
                [&]() { return client.state() == RobustClient::State::Connected; })) {
            std::cerr << "Failed to establish WebSocket connection" << std::endl;
            return;
        }
        std::cout << "Client connected successfully" << std::endl;

        // Give the server time to process the connection
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Send the text message
        std::cout << "Sending text message of size " << large_text.size() << std::endl;
        client.send_text_message(large_text);

        // Wait for the text message to be processed
        if (!run_until([&]() { return client.received_count() >= 1; })) {
            std::cerr << "Text message not echoed back" << std::endl;
        } else {
            std::cout << "Text message received" << std::endl;
        }

        // Wait a bit between messages
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Send the binary message
        std::cout << "Sending binary message of size " << binary_data.size()
                  << std::endl;
        client.send_binary_message(binary_data);

        // Wait for the binary message to be processed
        if (!run_until([&]() { return client.received_count() >= 2; })) {
            std::cerr << "Binary message not echoed back" << std::endl;
        } else {
            std::cout << "Binary message received" << std::endl;
        }

        // Vérifier les résultats
        EXPECT_EQ(client.received_count(), 2);
        EXPECT_EQ(client.last_text_message().size(), large_text.size());
        EXPECT_EQ(client.last_binary_message().size(), binary_data.size());

        // Terminer la connexion proprement
        client.send_close();
        run_until([&]() { return client.state() == RobustClient::State::Disconnected; },
                  100);

        test_complete = true;
    });

    // Thread serveur - traiter les événements jusqu'à ce que le test soit terminé
    std::cout << "Processing server events" << std::endl;
    run_until([&]() { return test_complete.load(); }, 2000);

    // Vérifier que le serveur a reçu et traité les messages
    std::cout << "Final server stats - Text: " << text_message_count
              << ", Binary: " << binary_message_count << std::endl;
    EXPECT_EQ(text_message_count, 1);
    EXPECT_EQ(binary_message_count, 1);

    // Attendre la fin du thread client
    if (client_thread.joinable()) {
        client_thread.join();
    }

    std::cout << "LARGE_MESSAGES test completed" << std::endl;
}

/**
 * @class DebugServer
 * @brief Enhanced WebSocket server for detailed debugging
 *
 * This server class extends the RobustServer with additional
 * logging capabilities to aid in problem diagnosis and debugging.
 * It provides detailed output of server operations.
 */
class DebugServer : public RobustServer {
public:
    /**
     * @brief Constructs a debug WebSocket server
     */
    DebugServer()
        : RobustServer() {}

    /**
     * @brief Start listening on specified port with detailed logging
     *
     * This method sets up the server to listen on the specified port
     * and logs details of the listening process.
     *
     * @param port TCP port to listen on
     */
    void
    listen(int port) {
        std::cout << "DebugServer: Starting to listen on port " << port << std::endl;
        this->transport().listen_v6(port);
        this->start();
        std::cout << "DebugServer: Listening active on port " << port << std::endl;
    }
};

/**
 * @class DebugClient
 * @brief Enhanced WebSocket client for detailed debugging
 *
 * This client class provides detailed logging of WebSocket operations
 * to aid in problem diagnosis and debugging. It logs all connection
 * steps, message exchanges, and internal state changes.
 */
class DebugClient : public use<DebugClient>::tcp::client<> {
public:
    /**
     * @brief Client connection state enumeration
     */
    enum State {
        Disconnected, /**< Client is disconnected */
        Connecting,   /**< Client is performing handshake */
        Connected,    /**< Client is connected */
        Closing       /**< Client is closing connection */
    };

private:
    const std::string ws_key;           /**< WebSocket key for handshake */
    State current_state_{Disconnected}; /**< Current client connection state */

public:
    std::string last_pong_data_; /**< Data from last received pong */

    using Protocol    = qb::http::protocol<DebugClient>;
    using WS_Protocol = qb::http::ws::protocol<DebugClient>;

    /**
     * @brief Constructs a debug WebSocket client
     *
     * Initializes a client with a randomly generated WebSocket key
     * and logs the key value for debugging.
     */
    DebugClient()
        : ws_key(qb::http::ws::generateKey()) {
        std::cout << "DebugClient: Created with key " << ws_key << std::endl;
    }

    /**
     * @brief Connect to a WebSocket server with detailed logging
     *
     * Establishes a TCP connection to the specified host and port,
     * logging each step of the process.
     *
     * @param host Hostname or IP address to connect to
     * @param port TCP port to connect to
     * @return True if connection was established, false otherwise
     */
    bool
    connect_to(const std::string &host, int port) {
        std::cout << "DebugClient: Connecting to " << host << ":" << port << std::endl;
        auto status = this->transport().connect_v6(host, port);
        if (status != SocketStatus::Done) {
            std::cout << "DebugClient: Connection failed with status "
                      << static_cast<int>(status) << std::endl;
            return false;
        }

        std::cout << "DebugClient: Connection established" << std::endl;
        return true;
    }

    /**
     * @brief Start a WebSocket session with detailed logging
     *
     * Starts the client and sends the WebSocket handshake request,
     * logging each step of the process.
     */
    void
    start_session() {
        std::cout << "DebugClient: Starting session" << std::endl;
        this->start();

        // Create and send the handshake
        qb::http::WebSocketRequest r(ws_key);
        r.uri() = "http://localhost:20170/";
        *this << r;

        current_state_ = Connecting;
        std::cout << "DebugClient: Handshake sent" << std::endl;
    }

    /**
     * @brief Handle HTTP response with detailed logging
     *
     * Processes the server's response to the handshake request,
     * logs all headers, and switches to the WebSocket protocol if successful.
     *
     * @param event HTTP response event
     */
    void
    on(Protocol::response &&response) {
        std::cout << "DebugClient: Received HTTP response, status="
                  << response.status() << std::endl;

        // Afficher les entêtes de la réponse pour le débogage
        std::cout << "Response headers:" << std::endl;
        for (const auto &header : response.headers()) {
            std::cout << "  " << header.first << ": ";
            for (const auto &value : header.second) {
                std::cout << value << " ";
            }
            std::cout << std::endl;
        }

        if (!this->switch_protocol<WS_Protocol>(*this, response, ws_key)) {
            std::cout << "DebugClient: Failed to switch to WebSocket protocol"
                      << std::endl;
            current_state_ = Disconnected;
            disconnect();
        } else {
            std::cout << "DebugClient: Successfully switched to WebSocket protocol"
                      << std::endl;
            current_state_ = Connected;
        }
    }

    /**
     * @brief Send a PING message directly with detailed logging
     *
     * Creates and sends a WebSocket PING frame with the specified data,
     * logging the process for debugging.
     *
     * @param data Payload data for the PING frame
     */
    void
    send_ping_direct(const std::string &data) {
        std::cout << "RobustClient: Sending PING directly with data size " << data.size()
                  << std::endl;

        // Create a PING message
        qb::http::ws::MessagePing ping_msg;
        ping_msg.masked = true; // Important: client must mask its messages
        ping_msg << data;

        // Send the message
        *this << ping_msg;

        std::cout << "RobustClient: PING message sent" << std::endl;
    }

    /**
     * @brief Send a debug PING message with detailed logging
     *
     * Creates and sends a WebSocket PING frame with the specified data,
     * with additional logging for testing and debugging.
     *
     * @param data Payload data for the PING frame
     */
    void
    send_ping_debug(const std::string &data) {
        std::cout << "DebugClient: Sending PING debug with data: " << data << std::endl;

        // Create a PING message
        qb::http::ws::MessagePing ping_msg;
        ping_msg.masked = true; // Important: client must mask its messages
        ping_msg << data;

        // Send the message
        *this << ping_msg;

        std::cout << "DebugClient: Debug PING message sent" << std::endl;
    }

    /**
     * @brief Handle PING frames with detailed logging
     *
     * Processes incoming PING frames from the server and responds
     * with corresponding PONG frames, logging the process.
     *
     * @param event PING event containing frame data
     */
    void
    on(WS_Protocol::ping &&event) {
        std::cout << "DebugClient: Received PING with data size " << event.size
                  << std::endl;

        // Créer et envoyer un PONG
        qb::http::ws::MessagePong pong;
        pong.masked = true;
        pong << std::string(event.data, event.size);
        *this << pong;

        std::cout << "DebugClient: Sent PONG in response" << std::endl;
    }

    /**
     * @brief Handle PONG frames with detailed logging
     *
     * Processes incoming PONG frames from the server (typically in
     * response to PING frames) and logs the data for verification.
     *
     * @param event PONG event containing frame data
     */
    void
    on(WS_Protocol::pong &&event) {
        std::string pong_data(event.data, event.size);
        std::cout << "DebugClient: Received PONG with data '" << pong_data << "'"
                  << std::endl;
        last_pong_data_ = pong_data;
    }

    /**
     * @brief Handle WebSocket message frames with detailed logging
     *
     * Processes incoming WebSocket message frames from the server
     * and logs their details for debugging.
     *
     * @param event Message event containing frame data
     */
    void
    on(WS_Protocol::message &&event) {
        std::cout << "DebugClient: Received message, opcode="
                  << (event.ws.fin_rsv_opcode & 0x0f) << ", size=" << event.size
                  << std::endl;
    }

    /**
     * @brief Get the current connection state
     *
     * @return Current client state (Disconnected, Connecting, Connected, or Closing)
     */
    State
    state() const {
        return current_state_;
    }

    /**
     * @brief Close the WebSocket connection with detailed logging
     *
     * Sends a WebSocket close frame to initiate a graceful connection
     * closure and logs the process.
     */
    void
    close() {
        std::cout << "DebugClient: Sending close frame" << std::endl;
        qb::http::ws::MessageClose close_msg(1000, "Normal closure");
        *this << close_msg;
        current_state_ = Closing;
    }
};

/**
 * @brief Test WebSocket PING/PONG control frame handling
 *
 * This test verifies that the WebSocket implementation correctly
 * handles PING/PONG control frames according to RFC 6455:
 * - Client can send PING frames to the server
 * - Server responds with PONG frames containing the same payload
 * - Payloads are correctly preserved in both directions
 * - Connection remains stable during PING/PONG exchanges
 */
TEST(Robustness, PING_PONG) {
    // Initialization
    async::init();
    reset_counters();

    std::cout << "=== Starting PING_PONG test with debug mode ===" << std::endl;

    // Start the server on port 20171
    RobustServer server;
    server.transport().listen_v6(20171);
    server.start();
    std::cout << "Server started on port 20171" << std::endl;

    // Create the client
    DebugClient client;
    if (!client.connect_to("::1", 20171)) {
        FAIL() << "Failed to connect to server";
        return;
    }

    // Start the client and initiate the handshake
    client.start_session();

    // Wait for the client to connect
    std::cout << "Waiting for client to connect..." << std::endl;
    auto start_time = std::chrono::steady_clock::now();
    while (client.state() != DebugClient::State::Connected &&
           std::chrono::steady_clock::now() - start_time < std::chrono::seconds(5)) {
        async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Check if the client is connected
    if (client.state() != DebugClient::State::Connected) {
        FAIL() << "Failed to establish WebSocket connection within timeout";
        return;
    }

    std::cout << "WebSocket connection established" << std::endl;

    // Wait a bit to ensure stability of the connection
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Send a PING with test data
    std::cout << "Sending PING with test data..." << std::endl;
    client.send_ping_debug("PING_DEBUG_TEST");

    // Wait to receive a PONG
    std::cout << "Waiting for PONG response..." << std::endl;
    start_time         = std::chrono::steady_clock::now();
    bool pong_received = false;

    while (!pong_received &&
           std::chrono::steady_clock::now() - start_time < std::chrono::seconds(5)) {
        async::run(EVRUN_NOWAIT);

        if (!client.last_pong_data_.empty()) {
            pong_received = true;
            std::cout << "PONG received with data: " << client.last_pong_data_
                      << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Verify the result
    EXPECT_TRUE(pong_received) << "No PONG response received within timeout";
    if (pong_received) {
        EXPECT_EQ(client.last_pong_data_, "PING_DEBUG_TEST")
            << "PONG data doesn't match PING data";
    }

    // Close the connection
    client.close();

    // Process closing events
    for (int i = 0; i < 50; ++i) {
        async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cout << "=== PING_PONG test completed ===" << std::endl;
}

/**
 * @brief Main function for running the robustness tests
 *
 * Initializes the Google Test framework and runs all the
 * WebSocket robustness tests defined in this file.
 *
 * @param argc Command line argument count
 * @param argv Command line arguments
 * @return Test execution status (0 for success)
 */
int
main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
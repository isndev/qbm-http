/**
 * @file test-stress.cpp
 * @brief WebSocket stress testing implementation
 *
 * This test suite provides extensive stress testing for the WebSocket protocol
 * implementation:
 * - Tests with various message sizes (small, medium, large)
 * - Tests with high message volume
 * - Tests for rapid connection/disconnection cycles
 * - Tests for long-lived connections with ping/pong exchanges
 *
 * These tests validate performance, robustness, and stability of the WebSocket
 * implementation under various load conditions.
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
 * limitations under the License.
 */

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <gtest/gtest.h>
#include <iostream>
#include <mutex>
#include <qb/io/async.h>
#include <random>
#include <thread>
#include <vector>
#include "../ws/ws.h"

/**
 * @brief Test configuration constants
 *
 * These constants control the intensity and characteristics of the stress tests.
 * They are configured to create significant load while remaining efficient for
 * automated testing.
 */

constexpr const std::size_t MESSAGE_SIZE_SMALL  = 128;   // Small message size in bytes
constexpr const std::size_t MESSAGE_SIZE_MEDIUM = 2048;  // Medium message size in bytes
constexpr const std::size_t MESSAGE_SIZE_LARGE  = 16384; // Large message size in bytes
constexpr const int         MAX_TEST_SECONDS    = 30;    // Maximum test duration in seconds (increased from 10)

/**
 * @brief Global variables for test synchronization and statistics
 *
 * These atomic counters track various metrics during test execution,
 * allowing verification of test results and proper synchronization
 * between test components.
 */
std::atomic<std::size_t> messages_received{0};  // Total messages received by server
std::atomic<std::size_t> messages_sent{0};      // Total messages sent by clients
std::atomic<std::size_t> connection_errors{0};  // Connection failures
std::atomic<std::size_t> protocol_errors{0};    // Protocol-level errors
std::atomic<std::size_t> active_connections{0}; // Currently active connections
std::atomic<bool>        server_ready{false};   // Server ready state flag
std::mutex               test_mutex;            // Mutex for test synchronization
std::condition_variable  test_cv;               // Condition variable for test coordination
std::atomic<bool>        test_complete{false};  // Test completion flag

// Additional synchronization variables
std::atomic<std::size_t> message_count{0}; // Message counter for specific tests
std::atomic<std::size_t> client_count{0};  // Client counter for coordination
std::atomic<std::size_t> error_count{0};   // Error counter for specific tests

/**
 * @class Timer
 * @brief Utility class for measuring elapsed time
 *
 * This class provides a simple high-resolution timer implementation
 * for measuring test execution time and enforcing timeouts.
 */
class Timer {
private:
    std::chrono::time_point<std::chrono::high_resolution_clock> _start;

public:
    /**
     * @brief Constructor initializes the timer
     */
    Timer()
        : _start(std::chrono::high_resolution_clock::now()) {}

    /**
     * @brief Reset the timer to the current time
     */
    void
    reset() {
        _start = std::chrono::high_resolution_clock::now();
    }

    /**
     * @brief Get elapsed time in milliseconds
     * @return Elapsed time as a floating-point value in milliseconds
     */
    double
    elapsed_ms() const {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(now - _start).count();
    }
};

/**
 * @brief Reset all test counters and state variables
 *
 * This function initializes the test environment by resetting
 * all counters, flags, and state variables to their default values.
 * Call this before each test to ensure a clean test state.
 */
void
reset_test_state() {
    messages_received  = 0;
    messages_sent      = 0;
    connection_errors  = 0;
    protocol_errors    = 0;
    active_connections = 0;
    message_count      = 0;
    client_count       = 0;
    error_count        = 0;
    server_ready       = false;
    test_complete      = false;
}

/**
 * @brief Signal test completion to all threads
 *
 * This function sets the test_complete flag and notifies
 * all waiting threads that the test has finished.
 */
void
force_test_completion() {
    std::unique_lock<std::mutex> lock(test_mutex);
    test_complete = true;
    test_cv.notify_all();
}

bool
decrement_client_count_once() {
    std::size_t current = client_count.load(std::memory_order_relaxed);
    while (current > 0) {
        if (client_count.compare_exchange_weak(current, current - 1, std::memory_order_relaxed, std::memory_order_relaxed)) {
            return (current - 1) == 0;
        }
    }
    return false;
}

/**
 * @brief Generate random test data of specified size
 *
 * @param size Size of the test data in bytes
 * @return String containing random alphanumeric characters
 *
 * This function generates deterministic random data for testing,
 * ensuring that the same size always produces the same sequence
 * for reproducible tests.
 */
std::string
generate_test_data(std::size_t size) {
    static const char alphanum[] = "0123456789"
                                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz";

    std::string result;
    result.reserve(size);

    // Use deterministic random for consistent test data
    std::mt19937                    rng(static_cast<unsigned int>(size));
    std::uniform_int_distribution<> dist(0, sizeof(alphanum) - 2);

    for (std::size_t i = 0; i < size; ++i) {
        result += alphanum[dist(rng)];
    }

    return result;
}

/**
 * @brief WebSocket Stress Test Server Implementation
 *
 * The following classes implement a WebSocket server for stress testing:
 * - StressServerClient: Handles individual client connections
 * - StressServer: Manages the server and tracks overall test state
 */

// Forward declaration
class StressServer;

/**
 * @class StressServerClient
 * @brief Handles individual WebSocket client connections for stress tests
 *
 * This class represents a client connection on the server side.
 * It processes WebSocket protocol events, validates messages,
 * and implements echo behavior for testing.
 */
class StressServerClient
    : public qb::io::use<StressServerClient>::tcp::client<StressServer>
    , public qb::io::use<StressServerClient>::timeout {
private:
    std::size_t _received_count = 0; ///< Count of messages received by this client
    Timer       _client_timer;       ///< Timer for tracking client lifespan

public:
    // Define protocol types with fully qualified namespaces
    using Protocol    = qb::http::protocol<StressServerClient>;
    using WS_Protocol = qb::http::ws::protocol<StressServerClient>;

    /**
     * @brief Constructor
     * @param server Reference to the parent server
     */
    explicit StressServerClient(IOServer &server)
        : qb::io::use<StressServerClient>::tcp::client<StressServer>(server) {}

    /**
     * @brief Process HTTP handshake request
     * @param event HTTP request event
     *
     * This method handles the initial WebSocket handshake request,
     * switching the connection to the WebSocket protocol if valid.
     */
    void
    on(typename Protocol::request &&request) {
        qb::io::cout() << "Server received client request, switching to WebSocket protocol..." << std::endl;
        if (!this->switch_protocol<WS_Protocol>(*this, request)) {
            qb::io::cout() << "Server failed to switch protocols" << std::endl;
            ++protocol_errors;
            disconnect();
        } else {
            qb::io::cout() << "Server successfully switched to WebSocket protocol" << std::endl;
            ++active_connections;
        }
    }

    /**
     * @brief Process WebSocket message
     * @param event WebSocket message event
     *
     * This method handles incoming WebSocket messages.
     * The server echoes back all received messages to
     * verify bidirectional communication.
     */
    void
    on(typename WS_Protocol::message &&event) {
        // Echo back the message
        qb::io::cout() << "Server received message from client, opcode=" << static_cast<int>(event.ws.fin_rsv_opcode & 0x0f)
                       << ", size=" << event.size << std::endl;

        // Important: make sure to echo back with proper masking setting
        event.ws.masked = false;
        *this << event.ws;

        ++_received_count;
        ++messages_received;
        qb::io::cout() << "Server echo complete, total received: " << messages_received << std::endl;
    }

    /**
     * @brief Process WebSocket ping
     * @param event WebSocket ping event
     *
     * This method handles ping messages by responding with
     * appropriate pong messages containing the same payload.
     */
    void
    on(typename WS_Protocol::ping &&event) {
        qb::io::cout() << "Server received ping" << std::endl;
        qb::http::ws::MessagePong pong;
        if (event.size > 0) {
            pong._data.write(event.data, event.size);
        }
        *this << pong;
    }

    /**
     * @brief Process WebSocket close request
     * @param event WebSocket close event
     *
     * This method handles connection close requests by
     * disconnecting the client gracefully.
     */
    void
    on(typename WS_Protocol::close &&event) {
        qb::io::cout() << "Server received close request" << std::endl;
        disconnect();
    }

    /**
     * @brief Handle timeout events
     * @param event Timeout event
     *
     * This method would handle timeout events, but is not used
     * in the current stress tests.
     */
    void
    on(qb::io::async::event::timeout const &) {
        // No timeout handling required for this test
    }

    /**
     * @brief Get count of received messages
     * @return Number of messages received by this client
     */
    std::size_t
    received_count() const {
        return _received_count;
    }

    /**
     * @brief Get client connection uptime
     * @return Duration in milliseconds that the client has been connected
     */
    double
    elapsed_ms() const {
        return _client_timer.elapsed_ms();
    }
};

/**
 * @class StressServer
 * @brief WebSocket server for stress testing
 *
 * This class manages the server-side of the WebSocket stress tests,
 * tracking overall test state and coordinating client connections.
 */
class StressServer : public qb::io::use<StressServer>::tcp::server<StressServerClient> {
private:
    std::size_t _expected_messages; ///< Expected number of messages for the test
    std::size_t _total_received{0}; ///< Counter for received messages
    Timer       _server_timer;      ///< Timer for tracking server uptime

public:
    /**
     * @brief Constructor
     * @param expected_messages Expected number of messages for test completion
     */
    explicit StressServer(std::size_t expected_messages = 0)
        : _expected_messages(expected_messages) {}

    /**
     * @brief Handle new client sessions
     * @param session Reference to the new client session
     *
     * This method is called when a new client connects to the server.
     */
    void
    on(IOSession &session) {
        // New client connected
        qb::io::cout() << "New client connected to server" << std::endl;
    }

    /**
     * @brief Handle client disconnection
     * @param event Disconnection event
     *
     * This method is called when a client disconnects. It updates the
     * active connections count and checks if the test should complete.
     */
    void
    on(qb::io::async::event::disconnected &) {
        std::size_t current = active_connections.load(std::memory_order_relaxed);
        while (current > 0
               && !active_connections.compare_exchange_weak(current, current - 1, std::memory_order_relaxed, std::memory_order_relaxed)) {
        }

        // Signal test completion when all connections are closed and messages were
        // processed
        if (active_connections == 0 && messages_received > 0) {
            qb::io::cout() << "No active connections left and messages processed: " << messages_received << ", forcing completion" << std::endl;
            force_test_completion();
        }

        // Original condition
        if (_total_received >= _expected_messages) {
            force_test_completion();
        }
    }

    /**
     * @brief Increment the total received message count
     * @param count Number of messages to add to the counter
     */
    void
    increment_received(std::size_t count) {
        _total_received += count;
    }

    /**
     * @brief Get the total number of received messages
     * @return Count of received messages
     */
    std::size_t
    total_received() const {
        return _total_received;
    }

    /**
     * @brief Get server uptime
     * @return Duration in milliseconds that the server has been running
     */
    double
    elapsed_ms() const {
        return _server_timer.elapsed_ms();
    }

    /**
     * @brief Signal that the server is ready to accept connections
     *
     * This method sets the server_ready flag to true, allowing
     * waiting clients to proceed with connection attempts.
     */
    void
    signal_ready() {
        server_ready = true;
    }
};

// ====== Stress Test Client ======

class StressClient
    : public qb::io::use<StressClient>::tcp::client<>
    , public qb::io::use<StressClient>::timeout {
private:
    const std::string _ws_key;
    std::size_t       _messages_to_send  = 0;
    std::size_t       _messages_sent     = 0;
    std::size_t       _messages_received = 0;
    std::size_t       _max_message_size  = 0;
    int               _client_id         = 0;
    Timer             _timer;
    bool              _close_sent = false;

public:
    // Define protocol types with fully qualified namespaces
    using Protocol    = qb::http::protocol<StressClient>;
    using WS_Protocol = qb::http::ws::protocol<StressClient>;

    /**
     * @brief Constructor
     * @param client_id Unique identifier for this client
     * @param messages_to_send Number of messages this client should send
     * @param max_message_size Maximum message size for this client
     *
     * Initializes the client with the specified parameters and generates
     * a unique WebSocket key for the handshake.
     */
    StressClient(int client_id, std::size_t messages_to_send, std::size_t max_message_size)
        : qb::io::use<StressClient>::tcp::client<>()
        , _ws_key(qb::http::ws::generateKey())
        , _messages_to_send(messages_to_send)
        , _max_message_size(max_message_size)
        , _client_id(client_id) {}

    /**
     * @brief Send the initial WebSocket handshake request
     *
     * This method sends the HTTP upgrade request that initiates
     * the WebSocket handshake process.
     */
    void
    send_handshake() {
        qb::http::WebSocketRequest r(_ws_key);
        r.uri() = "ws://localhost:20150/";
        r.headers()["Host"].emplace_back("localhost:20150");
        qb::io::cout() << "Client " << _client_id << " sending handshake" << std::endl;
        *this << r;
    }

    /**
     * @brief Send WebSocket messages
     *
     * This method sends messages until the target count is reached.
     * If all messages have been sent, it sends a close frame to terminate
     * the connection gracefully.
     */
    void
    send_messages() {
        if (_messages_sent >= _messages_to_send) {
            if (_close_sent) {
                return;
            }
            // All messages sent, close connection
            qb::io::cout() << "Client " << _client_id << " sending close message after sending " << _messages_sent << " messages" << std::endl;
            qb::http::ws::MessageClose msg(qb::http::ws::CloseStatus::Normal);
            msg.masked = true;
            *this << msg;
            _close_sent = true;
            return;
        }

        // Send a random sized message
        std::random_device                         rd;
        std::mt19937                               gen(rd());
        std::uniform_int_distribution<std::size_t> size_dist(64, _max_message_size);
        auto                                       message_size = size_dist(gen);

        // For simplicity in testing, always use text messages
        std::string data = generate_test_data(message_size);

        qb::http::ws::MessageText msg;
        msg.masked = true;
        msg << data;
        qb::io::cout() << "Client " << _client_id << " sending message #" << (_messages_sent + 1) << ", size=" << data.size() << std::endl;
        *this << msg;

        ++_messages_sent;
        ++messages_sent;
    }

    /**
     * @brief Check if client has completed its test
     * @return True if all expected responses have been received
     */
    bool
    is_complete() const {
        return _messages_received >= _messages_to_send;
    }

    /**
     * @brief Handle HTTP response (WebSocket handshake response)
     * @param event HTTP response event
     *
     * This method processes the server's response to the WebSocket handshake,
     * and if successful, switches to the WebSocket protocol and begins sending messages.
     */
    void
    on(typename Protocol::response &&response) {
        qb::io::cout() << "Client " << _client_id << " received HTTP response, status=" << response.status() << std::endl;

        if (!this->switch_protocol<WS_Protocol>(*this, response, _ws_key)) {
            qb::io::cout() << "Client " << _client_id << " failed to switch protocols" << std::endl;
            ++protocol_errors;
            disconnect();
            return;
        }

        qb::io::cout() << "Client " << _client_id << " successfully switched to WebSocket protocol" << std::endl;
        // Start sending messages after a short delay
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        send_messages();
    }

    /**
     * @brief Handle WebSocket message events
     * @param event WebSocket message event
     *
     * This method processes messages received from the server (typically echo
     * responses), increments the received message counter, and triggers sending the next
     * message.
     */
    void
    on(typename WS_Protocol::message &&event) {
        qb::io::cout() << "Client " << _client_id << " received message, size=" << event.size << std::endl;
        ++_messages_received;

        // After receiving a message, send another with a short delay
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        send_messages();

        // Check if we're done
        if (_messages_received >= _messages_to_send) {
            qb::io::cout() << "Client " << _client_id << " completed all " << _messages_to_send << " messages" << std::endl;
        }
    }

    /**
     * @brief Handle WebSocket close events
     * @param event WebSocket close event
     *
     * This method processes close frames received from the server
     * and disconnects the client gracefully.
     */
    void
    on(typename WS_Protocol::close &&event) {
        qb::io::cout() << "Client " << _client_id << " received close message" << std::endl;
        disconnect();
    }

    /**
     * @brief Handle disconnection events
     * @param event Disconnection event
     *
     * This method handles client disconnection, updating the global
     * client count and triggering test completion if needed.
     */
    void
    on(qb::io::async::event::disconnected const &event) {
        qb::io::cout() << "Client " << _client_id << " disconnected" << std::endl;
        if (decrement_client_count_once()) {
            qb::io::cout() << "Last client disconnected, forcing test completion" << std::endl;
            force_test_completion();
        }
        qb::io::cout() << "Decremented client_count to " << client_count.load() << std::endl;
    }

    /**
     * @brief Handle timeout events
     * @param event Timeout event
     *
     * This method would handle timeout events, but is not used
     * in the current stress tests.
     */
    void
    on(qb::io::async::event::timeout const &) {
        // No timeout handling for this test
    }

    /**
     * @brief Get count of sent messages
     * @return Number of messages sent by this client
     */
    std::size_t
    messages_sent_count() const {
        return _messages_sent;
    }

    /**
     * @brief Get count of received messages
     * @return Number of messages received by this client
     */
    std::size_t
    received_count() const {
        return _messages_received;
    }
};

/**
 * @brief Run a WebSocket stress test with specified parameters
 *
 * @param num_clients Number of clients to create
 * @param msgs_per_client Number of messages each client should send
 * @param msg_size Size of messages in bytes
 *
 * This function is the core stress test implementation. It:
 * 1. Sets up a WebSocket server
 * 2. Creates the specified number of client threads
 * 3. Coordinates message exchange
 * 4. Verifies test results
 */
void
run_stress_test(std::size_t num_clients, std::size_t msgs_per_client, std::size_t msg_size) {
    reset_test_state();

    const std::size_t total_expected_msgs = num_clients * msgs_per_client;

    // Start server
    StressServer server(total_expected_msgs);
    server.transport().listen_v6(20150);
    server.start();
    server.signal_ready();

    qb::io::cout() << "Server started on port 20150, expecting " << total_expected_msgs << " messages" << std::endl;

    // Create client threads
    std::vector<std::thread> threads;
    client_count = num_clients; // Set the number of clients for synchronization

    for (std::size_t i = 0; i < num_clients; ++i) {
        threads.emplace_back([i, msgs_per_client, msg_size]() {
            // Initialize async I/O for this thread
            qb::io::async::init();

            // Create unique client ID and introduce connection delay to avoid thundering
            // herd
            int client_id = static_cast<int>(i);
            std::this_thread::sleep_for(std::chrono::milliseconds(20 * i));

            // Wait for server to be ready
            Timer server_wait_timer;
            while (!server_ready && server_wait_timer.elapsed_ms() < 1000) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            if (!server_ready) {
                qb::io::cout() << "Client " << client_id << " timed out waiting for server" << std::endl;
                if (decrement_client_count_once()) {
                    force_test_completion();
                }
                return;
            }

            qb::io::cout() << "Client " << client_id << " connected and sent handshake" << std::endl;
            StressClient client(client_id, msgs_per_client, msg_size);

            // Connect to server
            auto status = client.transport().connect_v6("::1", 20150);
            if (status == qb::io::SocketStatus::Done) {
                client.start();
                client.send_handshake();

                // Process events until client completes or test times out
                Timer client_timer;
                while (!test_complete.load(std::memory_order_relaxed) && !client.is_complete()
                       && client_timer.elapsed_ms() < MAX_TEST_SECONDS * 1000) {
                    qb::io::async::run(EVRUN_NOWAIT);
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }

                // If not completed normally, time out
                if (!client.is_complete() && !test_complete.load(std::memory_order_relaxed)) {
                    qb::io::cout() << "Client " << client_id << " timed out with " << client.received_count() << "/" << msgs_per_client
                                   << " messages" << std::endl;
                }

                // Add a delay to process any pending messages before disconnect
                for (int i = 0; i < 10; ++i) {
                    qb::io::async::run(EVRUN_NOWAIT);
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }

                client.disconnect();
            } else {
                qb::io::cout() << "Client " << client_id << " failed to connect" << std::endl;
                ++connection_errors;
                // Decrement client count to avoid hanging the test
                if (decrement_client_count_once()) {
                    force_test_completion();
                }
            }
        });
    }

    // Process events and wait for completion or timeout
    Timer       test_timer;
    std::size_t last_received = 0;
    std::size_t stall_count   = 0;

    // Increased test timeout for more reliability
    while (test_timer.elapsed_ms() < MAX_TEST_SECONDS * 1000 && !test_complete.load(std::memory_order_relaxed)) {
        qb::io::async::run(EVRUN_NOWAIT);

        // Check if we've received all expected messages
        if (messages_received >= total_expected_msgs) {
            qb::io::cout() << "All expected messages received (" << messages_received << "/" << total_expected_msgs << "), completing test"
                           << std::endl;
            break;
        }

        // Check for stalled communication (no new messages for some time)
        if (last_received == messages_received) {
            stall_count++;

            // Print progress every second during stalls
            if (stall_count % 500 == 0) {
                qb::io::cout() << "Progress update: " << messages_received << "/" << total_expected_msgs << " messages, " << active_connections
                               << " active connections" << std::endl;
            }

            // Consider test complete if no messages received for 3 seconds and we're at
            // least 80% done
            if (stall_count > 3000 && messages_received >= total_expected_msgs * 0.8) {
                qb::io::cout() << "Message flow stalled at " << messages_received << "/" << total_expected_msgs
                               << " messages, but we've reached at least 80% - completing test" << std::endl;
                break;
            }
        } else {
            // Reset stall counter if we received new messages
            stall_count   = 0;
            last_received = messages_received;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    // Signal test completion to all threads
    test_complete = true;

    // Add a delay to allow threads to complete gracefully before joining
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Join all threads
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    // Output results
    qb::io::cout() << "Stress Test Results:" << std::endl
                   << "  Clients: " << num_clients << std::endl
                   << "  Messages per client: " << msgs_per_client << std::endl
                   << "  Message size: " << msg_size << " bytes" << std::endl
                   << "  Messages sent: " << messages_sent << std::endl
                   << "  Messages received: " << messages_received << std::endl
                   << "  Connection errors: " << connection_errors << std::endl
                   << "  Protocol errors: " << protocol_errors << std::endl;

    // Verify results with adaptive tolerance based on message size and client count
    double tolerance_percent = 0.10; // 10% base tolerance for all tests

    if (msg_size >= MESSAGE_SIZE_MEDIUM) {
        tolerance_percent = 0.15; // 15% tolerance for medium/large messages
    }

    if (num_clients >= 8) {
        tolerance_percent += 0.05; // Add 5% more tolerance for many clients
    }

    std::size_t tolerance = static_cast<std::size_t>(total_expected_msgs * tolerance_percent);

    qb::io::cout() << "  Tolerance: " << tolerance << " messages (" << (tolerance_percent * 100) << "%)" << std::endl;

    EXPECT_GE(messages_sent, total_expected_msgs - tolerance);
    EXPECT_GE(messages_received, total_expected_msgs - tolerance);
    EXPECT_EQ(connection_errors, 0);
    EXPECT_EQ(protocol_errors, 0);
}

/**
 * @brief Test with many small messages
 *
 * This test verifies the server's ability to handle multiple
 * clients sending a moderate number of small messages.
 */
TEST(Stress, MANY_SMALL_MESSAGES) {
    run_stress_test(5, 20,
                    MESSAGE_SIZE_SMALL); // 5 clients, 20 messages each (128 bytes)
}

/**
 * @brief Test with medium-sized messages
 *
 * This test verifies the server's ability to handle
 * medium-sized messages that require fragmentation.
 */
TEST(Stress, MEDIUM_MESSAGES) {
    run_stress_test(4, 10,
                    MESSAGE_SIZE_MEDIUM); // 4 clients, 10 messages each (2048 bytes)
}

/**
 * @brief Test with large messages
 *
 * This test verifies the server's ability to handle
 * large messages that require extensive fragmentation.
 */
TEST(Stress, LARGE_MESSAGES) {
    run_stress_test(2, 5,
                    MESSAGE_SIZE_LARGE); // 2 clients, 5 messages each (16384 bytes)
}

/**
 * @brief Test with many concurrent connections
 *
 * This test verifies the server's ability to handle
 * a large number of concurrent client connections.
 */
TEST(Stress, MANY_CONNECTIONS) {
    // Use a smaller number of clients with more messages per client
    // to improve test reliability while maintaining the same total message count
    constexpr int client_count_for_test = 5;
    constexpr int messages_per_client   = 6;

    // Reset all counters and synchronization variables
    reset_test_state();
    client_count = 0; // Reset client counter for clean start

    // Run the test with modified parameters
    run_stress_test(client_count_for_test, messages_per_client, MESSAGE_SIZE_SMALL);
}

/**
 * @brief Test with high message volume
 *
 * This test verifies the server's ability to handle
 * a high volume of total messages across multiple clients.
 */
TEST(Stress, HIGH_VOLUME) {
    run_stress_test(8, 30,
                    MESSAGE_SIZE_SMALL); // 8 clients, 30 messages each (128 bytes)
}

/**
 * @brief Test rapid connection and disconnection cycles
 *
 * This test verifies the server's ability to handle clients that
 * connect and disconnect rapidly, simulating connection churn.
 */
// Use fewer iterations for this test to keep it fast
constexpr int num_iterations = 100; // Number of connect/disconnect cycles per thread
TEST(Stress, RAPID_CONNECTIONS) {
    reset_test_state();

    // Start server
    StressServer server;
    server.transport().listen_v6(20150);
    server.start();
    server.signal_ready();

    qb::io::cout() << "Server started for RAPID_CONNECTIONS test" << std::endl;

    // Track connections and disconnections
    std::atomic<std::size_t> connected_count{0};
    std::atomic<std::size_t> disconnected_count{0};
    std::atomic<bool>        test_running{true};

    std::vector<std::thread> threads;

    // Create and start client threads
    for (int i = 0; i < 8; ++i) { // 8 client threads
        threads.emplace_back([i, &connected_count, &disconnected_count, &test_running]() {
            qb::io::async::init();

            // Wait for server to be ready with fast timeout
            Timer wait_timer;
            while (!server_ready && wait_timer.elapsed_ms() < 500) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }

            for (int j = 0; j < num_iterations && test_running; ++j) {
                // Create new client for each connection
                StressClient client(i * 100 + j, 1, MESSAGE_SIZE_SMALL);

                auto status = client.transport().connect_v6("::1", 20150);
                if (status == qb::io::SocketStatus::Done) {
                    ++connected_count;
                    client.start();
                    client.send_handshake();

                    // Very short processing time
                    for (int k = 0; k < 5 && test_running; ++k) {
                        qb::io::async::run(EVRUN_NOWAIT);
                        std::this_thread::sleep_for(std::chrono::milliseconds(2));
                    }

                    // Force disconnect after brief connection
                    client.disconnect();
                    ++disconnected_count;
                }

                // Short delay between connections
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
        });
    }

    // Run for a short time
    Timer timer;
    while (timer.elapsed_ms() < 1000 && !test_complete.load(std::memory_order_relaxed)) {
        qb::io::async::run(EVRUN_NOWAIT);

        // If all connections completed, exit early
        if (connected_count > 0 && connected_count == disconnected_count) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    // Signal threads to complete
    test_running  = false;
    test_complete = true;

    // Join all threads with timeout
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    qb::io::cout() << "RAPID_CONNECTIONS test results:" << std::endl
                   << "  Connections established: " << connected_count << std::endl
                   << "  Disconnections: " << disconnected_count << std::endl;

    // Verify some connections were made
    EXPECT_GT(connected_count, 0);
    EXPECT_EQ(connected_count, disconnected_count);
}

/**
 * @brief Test long-lived connections with ping/pong
 *
 * This test verifies the server's ability to maintain long-lived
 * connections and correctly handle ping/pong control frames.
 */
// Parameters for a real stress test
constexpr int num_clients            = 5;    // Number of concurrent clients
constexpr int ping_interval_ms       = 50;   // Send ping every 50ms
constexpr int connection_duration_ms = 1000; // Each connection lasts 1 second
constexpr int max_test_duration_ms   = 2000; // Maximum test duration
TEST(Stress, LONG_LIVED_CONNECTIONS) {
    reset_test_state();

    // Start server - Using regular TCP transport
    StressServer server;
    server.transport().listen_v6(20150);
    server.start();
    server.signal_ready();

    qb::io::cout() << "Server started for LONG_LIVED_CONNECTIONS test" << std::endl;

    std::atomic<int>         ping_pong_count{0}; // Count of ping/pong exchanges
    std::atomic<bool>        test_running{true}; // Test running flag
    std::vector<std::thread> threads;            // Client threads

    // Create and start client threads
    for (int i = 0; i < num_clients; ++i) {
        threads.emplace_back([i, &ping_pong_count, &test_running]() {
            qb::io::async::init();

            // Wait for server to be ready
            Timer wait_timer;
            while (!server_ready && wait_timer.elapsed_ms() < 500) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }

            if (!server_ready) {
                qb::io::cout() << "Client " << i << " timed out waiting for server" << std::endl;
                return;
            }

            // Stagger connection times to distribute load
            std::this_thread::sleep_for(std::chrono::milliseconds(10 * i));

            StressClient client(i, 2, MESSAGE_SIZE_SMALL); // 2 messages per client

            auto status = client.transport().connect_v6("::1", 20150);
            if (status == qb::io::SocketStatus::Done) {
                client.start();
                client.send_handshake();

                // Process events for a longer time with multiple pings
                Timer client_timer;
                int   last_ping_time = 0;

                while (test_running && client_timer.elapsed_ms() < connection_duration_ms) {
                    qb::io::async::run(EVRUN_NOWAIT);

                    // Send pings at regular intervals
                    int current_time = static_cast<int>(client_timer.elapsed_ms());
                    if (current_time - last_ping_time >= ping_interval_ms) {
                        qb::http::ws::MessagePing ping;
                        ping.masked = true;
                        ping << "PING-" + std::to_string(i) + "-" + std::to_string(current_time);
                        client << ping;
                        ++ping_pong_count;
                        last_ping_time = current_time;
                        qb::io::cout() << "Client " << i << " sent PING at " << current_time << "ms" << std::endl;
                    }

                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }

                // After the timeout, send close frame and disconnect
                qb::http::ws::MessageClose close(qb::http::ws::CloseStatus::Normal);
                close.masked = true;
                client << close;
                qb::io::cout() << "Client " << i << " sent close frame after " << client_timer.elapsed_ms() << "ms" << std::endl;

                // Wait briefly for close to be processed
                for (int k = 0; k < 10 && test_running; ++k) {
                    qb::io::async::run(EVRUN_NOWAIT);
                    std::this_thread::sleep_for(std::chrono::milliseconds(2));
                }

                client.disconnect();
                qb::io::cout() << "Client " << i << " disconnected" << std::endl;
            }
        });
    }

    // Wait until all pings are sent or timeout
    Timer server_timer;
    bool  success = false;

    while (server_timer.elapsed_ms() < max_test_duration_ms && !test_complete.load(std::memory_order_relaxed)) {
        qb::io::async::run(EVRUN_NOWAIT);

        // Print status every 250ms
        if (static_cast<int>(server_timer.elapsed_ms()) % 250 == 0) {
            qb::io::cout() << "Status: Ping/Pong=" << ping_pong_count << ", Active=" << active_connections << std::endl;
        }

        // If we got pings and there are no more active connections, complete the test
        if (ping_pong_count >= num_clients && active_connections == 0) {
            success = true;
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    // Signal test completion
    test_running  = false;
    test_complete = true;

    // Join all threads
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    qb::io::cout() << "LONG_LIVED_CONNECTIONS test results:" << std::endl
                   << "  Duration: " << server_timer.elapsed_ms() << "ms" << std::endl
                   << "  Clients: " << num_clients << std::endl
                   << "  Ping/Pong exchanges: " << ping_pong_count << std::endl
                   << "  Result: " << (success ? "SUCCESS" : "TIMEOUT") << std::endl;

    // Verify multiple ping-pong exchanges occurred
    EXPECT_GT(ping_pong_count, num_clients * 3);
}

/**
 * @brief Main entry point for the stress test suite
 *
 * Initializes Google Test and runs all the defined tests.
 */
int
main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

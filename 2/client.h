/**
 * @file client.h
 * @brief Modern HTTP/2 client implementation with elegant async API
 * @copyright Copyright (c) 2024 isndev. All rights reserved.
 * @license This software is licensed under the terms specified in the LICENSE file
 *          located in the root directory of the project.
 */

#pragma once

#include <memory>
#include <functional>
#include <vector>
#include <queue>
#include <string>
#include <unordered_map>
#include <atomic>
#include <future>
#include <chrono>

#include <qb/io/async.h>
#include <qb/io/protocol/handshake.h>
#include <qb/io/uri.h>
#include <qb/uuid.h>

#include "protocol/client.h"
#include "../request.h"
#include "../response.h"
#include "../logger.h"

namespace qb::http2 {

/**
 * @brief Response callback type for single requests
 */
using ResponseCallback = std::function<void(qb::http::Response)>;

/**
 * @brief Response callback type for batch requests
 */
using BatchResponseCallback = std::function<void(std::vector<qb::http::Response>)>;

/**
 * @brief Connection state callback
 */
using ConnectionCallback = std::function<void(bool connected, const std::string& error_message)>;

/**
 * @brief Request context for tracking pending requests
 */
struct RequestContext {
    qb::http::Request request;
    ResponseCallback callback;
    std::chrono::steady_clock::time_point created_at;
    uint32_t stream_id = 0;
    bool completed = false;
};

/**
 * @brief Batch request context for tracking multiple requests
 */
struct BatchRequestContext {
    std::vector<qb::http::Request> requests;
    BatchResponseCallback callback;
    std::vector<qb::http::Response> responses;
    std::chrono::steady_clock::time_point created_at;
    std::unordered_map<uint32_t, size_t> stream_to_index; // stream_id -> request index
    size_t completed_count = 0;
    bool all_completed = false;
};

/**
 * @brief Modern HTTP/2 client with elegant async API
 * 
 * This client provides a clean, modern interface for HTTP/2 communication:
 * - Automatic connection management with ALPN negotiation
 * - Internal stream ID management
 * - Support for concurrent requests
 * - Batch request processing
 * - Automatic reconnection on connection loss
 * - Built-in timeout handling
 * - Connection pooling ready design
 * 
 * Usage examples:
 * ```cpp
 * // Single request
 * auto client = http2::make_client("https://example.com");
 * client->push_request(request, [](auto response) {
 *     // Handle response
 * });
 * 
 * // Batch requests
 * client->push_requests(requests, [](auto responses) {
 *     // Handle all responses in order
 * });
 * ```
 */
class Client : public qb::io::async::tcp::client<Client, qb::io::transport::stcp>,
               public qb::io::use<Client>::timeout {
public:
    using H2Protocol = qb::protocol::http2::ClientHttp2Protocol<Client>;
    using HandshakeProtocol = qb::io::protocol::handshake<Client>;
    using BaseTcpClient = qb::io::async::tcp::client<Client, qb::io::transport::stcp>;

private:
    // Connection state
    qb::io::uri _base_uri;
    qb::uuid _client_id;
    std::string _host;
    uint16_t _port;
    bool _is_connected = false;
    bool _is_connecting = false;
    bool _handshake_completed = false;
    
    // Protocol handlers
    H2Protocol* _h2_protocol = nullptr;
    
    // Request management
    std::queue<std::unique_ptr<RequestContext>> _pending_requests;
    std::unordered_map<uint32_t, std::unique_ptr<RequestContext>> _active_requests;
    std::unordered_map<uint64_t, std::unique_ptr<BatchRequestContext>> _active_batches;
    uint64_t _next_batch_id = 1;
    
    // Configuration
    double _connect_timeout = 30.0;
    double _request_timeout = 60.0;
    size_t _max_concurrent_streams = 100;
    bool _auto_reconnect = true;
    
    // Callbacks
    ConnectionCallback _connection_callback;
    
    // Statistics
    uint64_t _total_requests{0};
    uint64_t _successful_requests{0};
    uint64_t _failed_requests{0};

public:
    /**
     * @brief Construct HTTP/2 client
     * @param base_uri Base URI for the connection (scheme, host, port)
     */
    explicit Client(const std::string& base_uri);
    
    /**
     * @brief Construct HTTP/2 client with URI object
     * @param uri Base URI for the connection
     */
    explicit Client(const qb::io::uri& uri);
    
    ~Client();

    // Disable copy and move (base class doesn't support them)
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) = delete;
    Client& operator=(Client&&) = delete;

    /**
     * @brief Connect to the server
     * @param callback Optional callback for connection status
     * @return true if connection attempt started, false if already connected/connecting
     */
    bool connect(ConnectionCallback callback = nullptr);
    
    /**
     * @brief Disconnect from server
     */
    void disconnect();
    
    /**
     * @brief Check if client is connected
     * @return true if connected and ready for requests
     */
    [[nodiscard]] bool is_connected() const noexcept { return _is_connected && _handshake_completed; }
    
    /**
     * @brief Check if client is connecting
     * @return true if connection attempt in progress
     */
    [[nodiscard]] bool is_connecting() const noexcept { return _is_connecting; }

    /**
     * @brief Send a single HTTP request
     * @param request HTTP request to send
     * @param callback Callback to handle the response
     * @return true if request was queued successfully
     */
    bool push_request(qb::http::Request request, ResponseCallback callback);
    
    /**
     * @brief Send multiple HTTP requests as a batch
     * @param requests Vector of HTTP requests to send
     * @param callback Callback to handle all responses (in same order as requests)
     * @return true if batch was queued successfully
     */
    bool push_requests(std::vector<qb::http::Request> requests, BatchResponseCallback callback);

    /**
     * @brief Set connection timeout
     * @param timeout_seconds Timeout in seconds
     */
    void set_connect_timeout(double timeout_seconds) { _connect_timeout = timeout_seconds; }
    
    /**
     * @brief Set request timeout
     * @param timeout_seconds Timeout in seconds
     */
    void set_request_timeout(double timeout_seconds) { _request_timeout = timeout_seconds; }
    
    /**
     * @brief Set maximum concurrent streams
     * @param max_streams Maximum number of concurrent streams
     */
    void set_max_concurrent_streams(size_t max_streams) { _max_concurrent_streams = max_streams; }
    
    /**
     * @brief Enable/disable automatic reconnection
     * @param enable Whether to automatically reconnect on connection loss
     */
    void set_auto_reconnect(bool enable) { _auto_reconnect = enable; }

    /**
     * @brief Get client statistics
     * @return Tuple of (total_requests, successful_requests, failed_requests)
     */
    [[nodiscard]] std::tuple<uint64_t, uint64_t, uint64_t> get_stats() const noexcept {
        return {_total_requests, _successful_requests, _failed_requests};
    }

    /**
     * @brief Get number of active requests
     * @return Number of requests currently being processed
     */
    [[nodiscard]] size_t get_active_request_count() const noexcept {
        return _active_requests.size();
    }

    /**
     * @brief Get base URI
     * @return Base URI for this client
     */
    [[nodiscard]] const qb::io::uri& get_base_uri() const noexcept { return _base_uri; }

    // Event handlers for qb-io framework
    void on(qb::io::async::event::handshake&&);
    void on(qb::http::Response response, uint64_t app_request_id);
    void on(const qb::protocol::http2::Http2StreamErrorEvent& event);
    void on(const qb::protocol::http2::Http2GoAwayEvent& event);
    void on(const qb::protocol::http2::Http2PushPromiseEvent& event);
    void on(const qb::protocol::http2::Http2ConnectionErrorEvent& event);
    void on(qb::io::async::event::timeout const&);
    void on(qb::io::async::event::disconnected const& event);
    void on(qb::io::async::event::dispose const&);

private:
    /**
     * @brief Initialize client from URI
     * @param uri URI to parse
     */
    void initialize_from_uri(const qb::io::uri& uri);
    
    /**
     * @brief Start connection attempt
     */
    void start_connection();
    
    /**
     * @brief Process pending requests queue
     */
    void process_pending_requests();
    
    /**
     * @brief Handle successful connection
     */
    void handle_connection_success();
    
    /**
     * @brief Handle connection failure
     * @param error_message Error description
     */
    void handle_connection_failure(const std::string& error_message);
    
    /**
     * @brief Complete a request with response
     * @param stream_id Stream ID of the request
     * @param response HTTP response
     */
    void complete_request(uint32_t stream_id, qb::http::Response response);
    
    /**
     * @brief Fail a request with error
     * @param stream_id Stream ID of the request
     * @param error_message Error description
     */
    void fail_request(uint32_t stream_id, const std::string& error_message);
    
    /**
     * @brief Fail all active requests
     * @param error_message Error description
     */
    void fail_all_requests(const std::string& error_message);
    
    /**
     * @brief Check and handle request timeouts
     */
    void check_request_timeouts();
    
    /**
     * @brief Attempt reconnection if auto-reconnect is enabled
     */
    void attempt_reconnection();
    
    /**
     * @brief Create error response
     * @param status HTTP status code
     * @param message Error message
     * @return Error response object
     */
    qb::http::Response create_error_response(qb::http::status status, const std::string& message);
};
using client = Client;

/**
 * @brief Create a shared HTTP/2 client
 * @param base_uri Base URI for the connection
 * @return Shared pointer to HTTP/2 client
 */
std::shared_ptr<Client> make_client(const std::string& base_uri);

/**
 * @brief Create a shared HTTP/2 client with URI object
 * @param uri Base URI for the connection
 * @return Shared pointer to HTTP/2 client
 */
std::shared_ptr<Client> make_client(const qb::io::uri& uri);

} // namespace qb::http2 
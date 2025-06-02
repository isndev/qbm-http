/**
 * @file qbm/http/2/client.cpp
 * @brief HTTP/2 client implementation for qb-io framework
 *
 * This file implements the HTTP/2 client functionality built on top of
 * the qb-io asynchronous framework. It includes:
 *
 * - High-level HTTP/2 client interface implementation
 * - Connection management with automatic reconnection
 * - Request queuing and multiplexing support
 * - Batch request processing capabilities
 * - Response callback handling and error management
 * - Timeout handling for connections and requests
 * - Integration with the HTTP/2 protocol layer
 * - Support for both single and batch request patterns
 *
 * The client provides an easy-to-use interface while leveraging the full
 * power of HTTP/2 multiplexing and the asynchronous I/O framework.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http2
 */

#include "client.h"
#include <algorithm>
#include <sstream>

namespace qb::http2 {

Client::Client(const std::string& base_uri) 
    : BaseTcpClient()
    , _client_id(qb::generate_random_uuid()) {
    initialize_from_uri(qb::io::uri(base_uri));
    LOG_HTTP_INFO_PA(_client_id, "HTTP/2 Client created for URI: " << base_uri);
}

Client::Client(const qb::io::uri& uri) 
    : BaseTcpClient()
    , _client_id(qb::generate_random_uuid()) {
    initialize_from_uri(uri);
    LOG_HTTP_INFO_PA(_client_id, "HTTP/2 Client created for URI: " << uri.source());
}

Client::~Client() {
    LOG_HTTP_DEBUG_PA(_client_id, "HTTP/2 Client destructor called");
    
    // Fail all pending and active requests
    fail_all_requests("Client destroyed");
    
    // Disconnect if connected
    if (_is_connected || _is_connecting) {
        disconnect();
    }
    
    LOG_HTTP_INFO_PA(_client_id, "HTTP/2 Client destroyed");
}

void Client::initialize_from_uri(const qb::io::uri& uri) {
    _base_uri = uri;
    _host = std::string(uri.host());
    
    // Parse port
    if (!uri.port().empty()) {
        try {
            _port = static_cast<uint16_t>(std::stoi(std::string(uri.port())));
        } catch (const std::exception&) {
            _port = (uri.scheme() == "https") ? 443 : 80;
        }
    } else {
        _port = (uri.scheme() == "https") ? 443 : 80;
    }
    
    // Validate scheme
    if (uri.scheme() != "https" && uri.scheme() != "http") {
        throw std::invalid_argument("HTTP/2 client only supports http and https schemes");
    }
    
    if (uri.scheme() == "http") {
        LOG_HTTP_WARN_PA(_client_id, "Using HTTP/2 over plain HTTP (h2c) - not recommended for production");
    }
}

bool Client::connect(ConnectionCallback callback) {
    if (_is_connected) {
        LOG_HTTP_DEBUG_PA(_client_id, "Already connected");
        if (callback) {
            callback(true, "");
        }
        return true;
    }
    
    if (_is_connecting) {
        LOG_HTTP_DEBUG_PA(_client_id, "Connection already in progress");
        return false;
    }
    
    _connection_callback = callback;
    _is_connecting = true;
    _handshake_completed = false;
    
    LOG_HTTP_INFO_PA(_client_id, "Starting connection to " << _host << ":" << _port);
    
    start_connection();
    return true;
}

void Client::disconnect() {
    LOG_HTTP_INFO_PA(_client_id, "Disconnecting client");
    
    _is_connected = false;
    _is_connecting = false;
    _handshake_completed = false;
    _h2_protocol = nullptr;
    
    // Fail all active requests
    fail_all_requests("Connection closed");
    
    // Close transport
    BaseTcpClient::disconnect();
}

bool Client::push_request(qb::http::Request request, ResponseCallback callback) {
    if (!callback) {
        LOG_HTTP_ERROR_PA(_client_id, "Request callback cannot be null");
        return false;
    }
    
    _total_requests++;
    
    // Create request context
    auto context = std::make_unique<RequestContext>();
    context->request = std::move(request);
    context->callback = callback;
    context->created_at = std::chrono::steady_clock::now();
    
    // Ensure request has proper URI if relative
    if (context->request.uri().host().empty()) {
        // Build absolute URI from base URI and request path
        std::string absolute_uri_str = std::string(_base_uri.scheme()) + "://" + std::string(_base_uri.host());
        if (!_base_uri.port().empty()) {
            absolute_uri_str += ":" + std::string(_base_uri.port());
        }
        if (!context->request.uri().path().empty()) {
            absolute_uri_str += std::string(context->request.uri().path());
        } else {
            absolute_uri_str += "/";
        }
        if (!context->request.uri().encoded_queries().empty()) {
            absolute_uri_str += "?" + std::string(context->request.uri().encoded_queries());
        }
        context->request.uri() = qb::io::uri(absolute_uri_str);
    }
    
    LOG_HTTP_DEBUG_PA(_client_id, "Queuing request: " << context->request.method() 
                      << " " << context->request.uri().path());
    
    // Queue the request
    _pending_requests.push(std::move(context));
    
    // If connected, process immediately
    if (is_connected()) {
        process_pending_requests();
    } else if (!_is_connecting) {
        // Auto-connect if not already connecting
        connect();
    }
    
    return true;
}

bool Client::push_requests(std::vector<qb::http::Request> requests, BatchResponseCallback callback) {
    if (requests.empty()) {
        LOG_HTTP_WARN_PA(_client_id, "Empty request batch");
        if (callback) {
            callback({});
        }
        return true;
    }
    
    if (!callback) {
        LOG_HTTP_ERROR_PA(_client_id, "Batch callback cannot be null");
        return false;
    }
    
    _total_requests += requests.size();
    
    // Create batch context
    auto batch_context = std::make_unique<BatchRequestContext>();
    batch_context->requests = std::move(requests);
    batch_context->callback = callback;
    batch_context->created_at = std::chrono::steady_clock::now();
    batch_context->responses.resize(batch_context->requests.size());
    
    uint64_t batch_id = _next_batch_id++;
    
    LOG_HTTP_DEBUG_PA(_client_id, "Queuing batch request with " << batch_context->requests.size() 
                      << " requests (batch ID: " << batch_id << ")");
    
    // Queue individual requests with batch tracking
    for (size_t i = 0; i < batch_context->requests.size(); ++i) {
        auto& req = batch_context->requests[i];
        
        // Ensure request has proper URI if relative
        if (req.uri().host().empty()) {
            std::string absolute_uri_str = std::string(_base_uri.scheme()) + "://" + std::string(_base_uri.host());
            if (!_base_uri.port().empty()) {
                absolute_uri_str += ":" + std::string(_base_uri.port());
            }
            if (!req.uri().path().empty()) {
                absolute_uri_str += std::string(req.uri().path());
            } else {
                absolute_uri_str += "/";
            }
            if (!req.uri().encoded_queries().empty()) {
                absolute_uri_str += "?" + std::string(req.uri().encoded_queries());
            }
            req.uri() = qb::io::uri(absolute_uri_str);
        }
        
        auto context = std::make_unique<RequestContext>();
        context->request = std::move(req);
        context->created_at = batch_context->created_at;
        
        // Create callback that handles batch completion
        context->callback = [this, batch_id, i](qb::http::Response response) {
            auto batch_it = _active_batches.find(batch_id);
            if (batch_it == _active_batches.end()) {
                LOG_HTTP_WARN_PA(_client_id, "Received response for unknown batch " << batch_id);
                return;
            }
            
            auto& batch = *batch_it->second;
            batch.responses[i] = std::move(response);
            batch.completed_count++;
            
            LOG_HTTP_DEBUG_PA(_client_id, "Batch " << batch_id << " progress: " 
                              << batch.completed_count << "/" << batch.requests.size());
            
            // Check if batch is complete
            if (batch.completed_count == batch.requests.size() && !batch.all_completed) {
                batch.all_completed = true;
                LOG_HTTP_DEBUG_PA(_client_id, "Batch " << batch_id << " completed");
                
                // Call batch callback
                batch.callback(std::move(batch.responses));
                
                // Remove batch context
                _active_batches.erase(batch_it);
            }
        };
        
        _pending_requests.push(std::move(context));
    }
    
    // Store batch context
    _active_batches[batch_id] = std::move(batch_context);
    
    // If connected, process immediately
    if (is_connected()) {
        process_pending_requests();
    } else if (!_is_connecting) {
        // Auto-connect if not already connecting
        connect();
    }
    
    return true;
}

void Client::start_connection() {
    this->setTimeout(_connect_timeout);
    
    // Switch to handshake protocol first
    this->template switch_protocol<HandshakeProtocol>(*this);
    qb::io::transport::stcp::transport_io_type socket;
    socket.init();
    socket.set_alpn_protocols({"h2"});
    qb::io::async::tcp::connect<qb::io::transport::stcp::transport_io_type>(
        std::move(socket),
        _base_uri,
        [this](qb::io::transport::stcp::transport_io_type&& transport_socket) {
            if (!transport_socket.is_open() || !transport_socket.ssl_handle()) {
                handle_connection_failure("TCP/SSL connection failed");
                return;
            }
            transport_socket.set_alpn_protocols({"h2"});
            LOG_HTTP_DEBUG_PA(_client_id, "TCP/SSL connection established, starting handshake");
            this->transport() = std::move(transport_socket);
            this->start(); // Start handshake protocol
        },
        _connect_timeout
    );
}

void Client::process_pending_requests() {
    if (!is_connected() || !_h2_protocol) {
        return;
    }
    
    // Process pending requests up to concurrent limit
    while (!_pending_requests.empty() && 
           _active_requests.size() < _max_concurrent_streams) {
        
        auto context = std::move(_pending_requests.front());
        _pending_requests.pop();
        
        // Send request via HTTP/2 protocol
        uint64_t app_request_id = reinterpret_cast<uint64_t>(context.get());
        
        if (_h2_protocol->send_request(std::move(context->request), app_request_id)) {
            // Store context with app_request_id as key (will be mapped to stream_id)
            _active_requests[static_cast<uint32_t>(app_request_id)] = std::move(context);
            
            LOG_HTTP_DEBUG_PA(_client_id, "Request sent successfully (app_id: " << app_request_id << ")");
        } else {
            LOG_HTTP_ERROR_PA(_client_id, "Failed to send request");
            
            // Create error response
            auto error_response = create_error_response(
                qb::http::status::SERVICE_UNAVAILABLE, 
                "Failed to send HTTP/2 request"
            );
            
            context->callback(std::move(error_response));
            _failed_requests++;
        }
    }
}

void Client::handle_connection_success() {
    LOG_HTTP_INFO_PA(_client_id, "HTTP/2 connection established successfully");
    
    _is_connected = true;
    _is_connecting = false;
    _handshake_completed = true;
    
    if (_connection_callback) {
        _connection_callback(true, "");
        _connection_callback = nullptr;
    }
    
    // Process any pending requests
    process_pending_requests();
}

void Client::handle_connection_failure(const std::string& error_message) {
    LOG_HTTP_ERROR_PA(_client_id, "Connection failed: " << error_message);
    
    _is_connected = false;
    _is_connecting = false;
    _handshake_completed = false;
    _h2_protocol = nullptr;
    
    if (_connection_callback) {
        _connection_callback(false, error_message);
        _connection_callback = nullptr;
    }
    
    // Fail all pending requests
    fail_all_requests("Connection failed: " + error_message);
    
    // Attempt reconnection if enabled
    if (_auto_reconnect && (!_pending_requests.empty() || !_active_requests.empty())) {
        attempt_reconnection();
    }
}

void Client::complete_request(uint32_t stream_id, qb::http::Response response) {
    // Find request by stream_id (which should match app_request_id)
    auto it = _active_requests.find(stream_id);
    if (it == _active_requests.end()) {
        LOG_HTTP_WARN_PA(_client_id, "Received response for unknown stream " << stream_id);
        return;
    }
    
    auto context = std::move(it->second);
    _active_requests.erase(it);
    
    LOG_HTTP_DEBUG_PA(_client_id, "Request completed successfully (stream: " << stream_id << ")");
    
    _successful_requests++;
    context->callback(std::move(response));
    
    // Process more pending requests if any
    process_pending_requests();
}

void Client::fail_request(uint32_t stream_id, const std::string& error_message) {
    auto it = _active_requests.find(stream_id);
    if (it == _active_requests.end()) {
        LOG_HTTP_WARN_PA(_client_id, "Tried to fail unknown stream " << stream_id);
        return;
    }
    
    auto context = std::move(it->second);
    _active_requests.erase(it);
    
    LOG_HTTP_WARN_PA(_client_id, "Request failed (stream: " << stream_id << "): " << error_message);
    
    _failed_requests++;
    
    auto error_response = create_error_response(
        qb::http::status::BAD_GATEWAY, 
        error_message
    );
    
    context->callback(std::move(error_response));
}

void Client::fail_all_requests(const std::string& error_message) {
    LOG_HTTP_WARN_PA(_client_id, "Failing all requests: " << error_message);
    
    // Fail active requests
    for (auto& [stream_id, context] : _active_requests) {
        _failed_requests++;
        
        auto error_response = create_error_response(
            qb::http::status::SERVICE_UNAVAILABLE, 
            error_message
        );
        
        context->callback(std::move(error_response));
    }
    _active_requests.clear();
    
    // Fail pending requests
    while (!_pending_requests.empty()) {
        auto context = std::move(_pending_requests.front());
        _pending_requests.pop();
        
        _failed_requests++;
        
        auto error_response = create_error_response(
            qb::http::status::SERVICE_UNAVAILABLE, 
            error_message
        );
        
        context->callback(std::move(error_response));
    }
    
    // Fail incomplete batches
    for (auto& [batch_id, batch_context] : _active_batches) {
        if (!batch_context->all_completed) {
            LOG_HTTP_WARN_PA(_client_id, "Failing incomplete batch " << batch_id);
            
            // Fill remaining responses with errors
            for (size_t i = 0; i < batch_context->responses.size(); ++i) {
                if (batch_context->responses[i].status().code() == 0) { // Not set yet
                    batch_context->responses[i] = create_error_response(
                        qb::http::status::SERVICE_UNAVAILABLE, 
                        error_message
                    );
                }
            }
            
            batch_context->callback(std::move(batch_context->responses));
        }
    }
    _active_batches.clear();
}

void Client::check_request_timeouts() {
    auto now = std::chrono::steady_clock::now();
    auto timeout_duration = std::chrono::duration<double>(_request_timeout);
    
    // Check active requests for timeouts
    std::vector<uint32_t> timed_out_streams;
    
    for (const auto& [stream_id, context] : _active_requests) {
        if (now - context->created_at > timeout_duration) {
            timed_out_streams.push_back(stream_id);
        }
    }
    
    for (uint32_t stream_id : timed_out_streams) {
        fail_request(stream_id, "Request timeout");
    }
    
    // Check pending requests for timeouts
    std::queue<std::unique_ptr<RequestContext>> non_timed_out_requests;
    
    while (!_pending_requests.empty()) {
        auto context = std::move(_pending_requests.front());
        _pending_requests.pop();
        
        if (now - context->created_at > timeout_duration) {
            LOG_HTTP_WARN_PA(_client_id, "Pending request timed out");
            _failed_requests++;
            
            auto error_response = create_error_response(
                qb::http::status::REQUEST_TIMEOUT, 
                "Request timeout while pending"
            );
            
            context->callback(std::move(error_response));
        } else {
            non_timed_out_requests.push(std::move(context));
        }
    }
    
    _pending_requests = std::move(non_timed_out_requests);
}

void Client::attempt_reconnection() {
    if (_is_connecting || _is_connected) {
        return;
    }
    
    LOG_HTTP_INFO_PA(_client_id, "Attempting automatic reconnection");
    
    // Add a small delay before reconnecting
    // In a real implementation, you might want exponential backoff
    connect();
}

qb::http::Response Client::create_error_response(qb::http::status status, const std::string& message) {
    qb::http::Response response;
    response.status() = status;
    response.body() = message;
    response.add_header("content-type", "text/plain");
    response.add_header("content-length", std::to_string(message.length()));
    return response;
}

// Event handlers for qb-io framework

void Client::on(qb::io::async::event::handshake&&) {
    LOG_HTTP_DEBUG_PA(_client_id, "SSL handshake completed");
    
    // Check ALPN negotiation
    auto alpn_selected = this->transport().get_alpn_selected_protocol();
    
    LOG_HTTP_INFO_PA(_client_id, "ALPN negotiated: " << (alpn_selected.empty() ? "none" : alpn_selected));
    
    if (alpn_selected == "h2") {
        // Switch to HTTP/2 protocol - pass nullptr for single request since we handle requests differently
        _h2_protocol = this->template switch_protocol<H2Protocol>(*this, nullptr);
        if (_h2_protocol) {
            LOG_HTTP_DEBUG_PA(_client_id, "HTTP/2 protocol switched successfully");
            
            // ✅ Let the framework handle the preface automatically
            // The framework will send the HTTP/2 connection preface when appropriate
            
            handle_connection_success();
        } else {
            handle_connection_failure("Failed to initialize HTTP/2 protocol");
        }
    } else {
        handle_connection_failure("ALPN did not negotiate HTTP/2 (h2). Got: '" + alpn_selected + "'");
    }
}

void Client::on(qb::http::Response response, uint64_t app_request_id) {
    LOG_HTTP_DEBUG_PA(_client_id, "Received HTTP response (app_id: " << app_request_id << ")");
    complete_request(static_cast<uint32_t>(app_request_id), std::move(response));
}

void Client::on(const qb::protocol::http2::Http2StreamErrorEvent& event) {
    LOG_HTTP_WARN_PA(_client_id, "HTTP/2 stream error on stream " << event.stream_id 
                     << ": " << event.message);
    fail_request(event.stream_id, "Stream error: " + event.message);
}

void Client::on(const qb::protocol::http2::Http2GoAwayEvent& event) {
    LOG_HTTP_WARN_PA(_client_id, "Received GOAWAY frame: " << event.debug_data);
    
    std::string error_msg = "Server sent GOAWAY: " + event.debug_data;
    fail_all_requests(error_msg);
    
    // Disconnect and potentially reconnect
    disconnect();
    
    if (_auto_reconnect && (!_pending_requests.empty() || !_active_requests.empty())) {
        attempt_reconnection();
    }
}

void Client::on(const qb::protocol::http2::Http2PushPromiseEvent& event) {
    LOG_HTTP_INFO_PA(_client_id, "Received PUSH_PROMISE for stream " << event.promised_stream_id);
    
    // Auto-reject server push by default
    if (_h2_protocol) {
        _h2_protocol->application_reject_push(event.promised_stream_id);
    }
}

void Client::on(const qb::protocol::http2::Http2ConnectionErrorEvent& event) {
    LOG_HTTP_ERROR_PA(_client_id, "HTTP/2 connection error: " << event.message);
    
    std::string error_msg = "Connection error: " + event.message;
    fail_all_requests(error_msg);
    
    disconnect();
    
    if (_auto_reconnect && (!_pending_requests.empty() || !_active_requests.empty())) {
        attempt_reconnection();
    }
}

void Client::on(qb::io::async::event::timeout const&) {
    LOG_HTTP_WARN_PA(_client_id, "Connection timeout");
    
    if (!_handshake_completed) {
        handle_connection_failure("Connection timeout");
    } else {
        // Check for request timeouts
        check_request_timeouts();
    }
}

void Client::on(qb::io::async::event::disconnected const& event) {
    LOG_HTTP_INFO_PA(_client_id, "Disconnected (reason: " << event.reason << ")");
    
    std::string error_msg = "Connection lost";
    if (event.reason != 0) {
        error_msg += " (reason: " + std::to_string(event.reason) + ")";
    }
    
    _is_connected = false;
    _handshake_completed = false;
    _h2_protocol = nullptr;
    
    fail_all_requests(error_msg);
    
    if (_auto_reconnect && (!_pending_requests.empty() || !_active_requests.empty())) {
        attempt_reconnection();
    }
}

void Client::on(qb::io::async::event::dispose const&) {
    LOG_HTTP_DEBUG_PA(_client_id, "Client disposal event");
    
    fail_all_requests("Client disposed");
    
    _is_connected = false;
    _is_connecting = false;
    _handshake_completed = false;
    _h2_protocol = nullptr;
}

// Factory functions

std::shared_ptr<Client> make_client(const std::string& base_uri) {
    return std::make_shared<Client>(base_uri);
}

std::shared_ptr<Client> make_client(const qb::io::uri& uri) {
    return std::make_shared<Client>(uri);
}

} // namespace qb::http2 
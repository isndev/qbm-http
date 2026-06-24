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
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http2
 */

#include "client.h"
#include <algorithm>
#include <charconv> // For std::from_chars - faster than std::stoi, no exceptions
#include <limits>
#include <sstream>

#include "../origin.h"

namespace qb::http2 {

Client::Client(const std::string &base_uri)
    : BaseTcpClient()
    , _client_id(qb::generate_random_uuid()) {
    initialize_from_uri(qb::io::uri(base_uri));
    LOG_HTTP_INFO_PA(_client_id, "HTTP/2 Client created for URI: " << base_uri);
}

Client::Client(const qb::io::uri &uri)
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

void
Client::initialize_from_uri(const qb::io::uri &uri) {
    _base_uri = uri;
    _host     = std::string(uri.host());

    // This implementation is TLS+ALPN only; plaintext h2c is not supported.
    if (!qb::http::origin::scheme_eq(uri.scheme(), "https")) {
        throw std::invalid_argument("HTTP/2 client only supports https scheme");
    }

    // Parse port using std::from_chars for better performance and no exceptions
    if (!uri.port().empty()) {
        std::string port_str   = std::string(uri.port());
        int         port_value = 0;
        auto [ptr, ec]         = std::from_chars(port_str.data(), port_str.data() + port_str.size(), port_value);
        if (ec == std::errc{} && port_value > 0 && port_value <= 65535) {
            _port = static_cast<uint16_t>(port_value);
        } else {
            _port = 443;
        }
    } else {
        _port = 443;
    }
}

bool
Client::connect(ConnectionCallback callback) {
    if (_is_connected) {
        LOG_HTTP_DEBUG_PA(_client_id, "Already connected");
        if (callback) {
            callback(true, "");
        }
        return true;
    }

    if (_is_connecting) {
        LOG_HTTP_DEBUG_PA(_client_id, "Connection already in progress");
        if (callback) {
            _connection_callbacks.push_back(std::move(callback));
        }
        return true;
    }

    if (callback) {
        _connection_callbacks.push_back(std::move(callback));
    }
    _is_connecting       = true;
    _handshake_completed = false;

    LOG_HTTP_INFO_PA(_client_id, "Starting connection to " << _host << ":" << _port);

    start_connection();
    return true;
}

void
Client::disconnect() {
    LOG_HTTP_INFO_PA(_client_id, "Disconnecting client");

    _is_connected                        = false;
    _is_connecting                       = false;
    _handshake_completed                 = false;
    _received_graceful_goaway            = false;
    _preserve_pending_on_next_disconnect = false;
    _h2_protocol                         = nullptr;

    // Fail all active requests
    fail_all_requests("Connection closed");

    // Close transport
    BaseTcpClient::disconnect();
}

void
Client::ensure_absolute_uri(qb::http::Request &request) {
    if (!request.uri().host().empty()) {
        return;
    }
    std::string absolute_uri_str = std::string(_base_uri.scheme()) + "://" + std::string(_base_uri.host());
    if (!_base_uri.port().empty()) {
        absolute_uri_str += ":" + std::string(_base_uri.port());
    }
    if (!request.uri().path().empty()) {
        absolute_uri_str += std::string(request.uri().path());
    } else {
        absolute_uri_str += "/";
    }
    if (!request.uri().encoded_queries().empty()) {
        absolute_uri_str += "?" + std::string(request.uri().encoded_queries());
    }
    request.uri() = qb::io::uri(absolute_uri_str);
}

std::optional<qb::http::Response>
Client::prepare_request(qb::http::Request &request) {
    ensure_absolute_uri(request);
    if (request.uri().host().empty()) {
        return create_error_response(qb::http::status::BAD_REQUEST, "HTTP/2 request URI is missing a host");
    }
    if (!qb::http::origin::scheme_eq(request.uri().scheme(), "https")) {
        return create_error_response(qb::http::status::BAD_REQUEST, "HTTP/2 request URI must use https");
    }
    if (!qb::http::origin::same(request.uri(), _base_uri)) {
        return create_error_response(qb::http::status::BAD_REQUEST, "HTTP/2 persistent client only accepts same-origin requests");
    }
    return std::nullopt;
}

bool
Client::push_request(qb::http::Request request, ResponseCallback callback) {
    if (!callback) {
        LOG_HTTP_ERROR_PA(_client_id, "Request callback cannot be null");
        return false;
    }

    _total_requests++;

    if (auto error = prepare_request(request)) {
        ++_failed_requests;
        callback(std::move(*error));
        return true;
    }

    // Bound the outstanding (pending + active) request set so a disconnected or saturated
    // client cannot grow the pending queue without limit (DoS guard; matches http1/http3).
    if (_pending_requests.size() + _active_requests.size() >= _max_pending_requests) {
        ++_failed_requests;
        callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "HTTP/2 client pending request limit reached"));
        return false;
    }

    // Create request context
    auto context        = std::make_unique<RequestContext>();
    context->request    = std::move(request);
    context->callback   = callback;
    context->created_at = std::chrono::steady_clock::now();

    LOG_HTTP_DEBUG_PA(_client_id, "Queuing request: " << context->request.method() << " " << context->request.uri().path());

    // Queue the request
    _pending_requests.push_back(std::move(context));
    arm_request_timeout();

    // If connected, process immediately
    if (is_connected()) {
        process_pending_requests();
    } else if (!_is_connecting) {
        // Auto-connect if not already connecting
        connect(nullptr);
    }

    return true;
}

bool
Client::push_requests(std::vector<qb::http::Request> requests, BatchResponseCallback callback) {
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
    auto batch_context        = std::make_unique<BatchRequestContext>();
    batch_context->requests   = std::move(requests);
    batch_context->callback   = callback;
    batch_context->created_at = std::chrono::steady_clock::now();
    batch_context->responses.resize(batch_context->requests.size());

    // Reject the whole batch up-front if it would exceed the outstanding-request bound (DoS guard).
    if (_pending_requests.size() + _active_requests.size() + batch_context->requests.size() > _max_pending_requests) {
        _failed_requests += batch_context->requests.size();
        std::vector<qb::http::Response> responses;
        responses.reserve(batch_context->requests.size());
        for (size_t i = 0; i < batch_context->requests.size(); ++i) {
            responses.push_back(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "HTTP/2 client pending request limit reached"));
        }
        callback(std::move(responses));
        return false;
    }

    uint64_t batch_id = _next_batch_id++;

    LOG_HTTP_DEBUG_PA(_client_id,
                      "Queuing batch request with " << batch_context->requests.size() << " requests (batch ID: " << batch_id << ")");

    // Queue individual requests with batch tracking
    for (size_t i = 0; i < batch_context->requests.size(); ++i) {
        auto &req = batch_context->requests[i];

        if (auto error = prepare_request(req)) {
            ++_failed_requests;
            batch_context->responses[i] = std::move(*error);
            ++batch_context->completed_count;
            continue;
        }

        auto context        = std::make_unique<RequestContext>();
        context->request    = std::move(req);
        context->created_at = batch_context->created_at;

        // Create callback that handles batch completion
        context->callback = [this, batch_id, i](qb::http::Response response) {
            auto batch_it = _active_batches.find(batch_id);
            if (batch_it == _active_batches.end()) {
                LOG_HTTP_WARN_PA(_client_id, "Received response for unknown batch " << batch_id);
                return;
            }

            auto &batch        = *batch_it->second;
            batch.responses[i] = std::move(response);
            batch.completed_count++;

            LOG_HTTP_DEBUG_PA(_client_id, "Batch " << batch_id << " progress: " << batch.completed_count << "/" << batch.requests.size());

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

        _pending_requests.push_back(std::move(context));
        arm_request_timeout();
    }

    if (batch_context->completed_count == batch_context->requests.size()) {
        batch_context->all_completed = true;
        batch_context->callback(std::move(batch_context->responses));
        return true;
    }

    // Store batch context
    _active_batches[batch_id] = std::move(batch_context);

    // If connected, process immediately
    if (is_connected()) {
        process_pending_requests();
    } else if (!_is_connecting) {
        // Auto-connect if not already connecting
        connect(nullptr);
    }

    return true;
}

void
Client::start_connection() {
    _connect_started_at = std::chrono::steady_clock::now();
    arm_request_timeout();

    // Switch to handshake protocol first
    this->template switch_protocol<HandshakeProtocol>(*this);
    qb::io::transport::stcp::transport_io_type socket;
    socket.init();
    socket.set_alpn_protocols({"h2"});
    auto weak_self = weak_from_this();
    qb::io::async::tcp::connect<qb::io::transport::stcp::transport_io_type>(
        std::move(socket), _base_uri,
        [weak_self](qb::io::transport::stcp::transport_io_type &&transport_socket) {
            auto self = weak_self.lock();
            if (!self) {
                return;
            }
            if (!transport_socket.is_open() || !transport_socket.ssl_handle()) {
                self->handle_connection_failure("TCP/SSL connection failed");
                return;
            }
            transport_socket.set_alpn_protocols({"h2"});
            LOG_HTTP_DEBUG_PA(self->_client_id, "TCP/SSL connection established, starting handshake");
            self->transport() = std::move(transport_socket);
            self->start(); // Start handshake protocol
        },
        _connect_timeout, _verify_peer);
}

void
Client::process_pending_requests() {
    if (!is_connected() || !_h2_protocol || _received_graceful_goaway) {
        return;
    }

    // Process pending requests up to concurrent limit
    while (!_pending_requests.empty() && _active_requests.size() < _max_concurrent_streams) {
        auto context = std::move(_pending_requests.front());
        _pending_requests.pop_front();

        // Send request via HTTP/2 protocol
        // SECURITY FIX: Use atomic counter instead of pointer casting for portable code
        // The old code used reinterpret_cast<uint64_t>(context.get()) which is non-portable
        // (undefined behavior on 32-bit platforms where sizeof(void*) != sizeof(uint64_t))
        static std::atomic<uint32_t> next_request_id{1};
        uint32_t                     app_request_id = next_request_id.fetch_add(1, std::memory_order_relaxed);

        if (_h2_protocol->send_request(std::move(context->request), app_request_id)) {
            context->stream_id = _h2_protocol->last_initiated_stream_id();
            // Store context with app_request_id as key (will be mapped to stream_id)
            _active_requests[app_request_id] = std::move(context);

            LOG_HTTP_DEBUG_PA(_client_id, "Request sent successfully (app_id: " << app_request_id << ")");
        } else {
            LOG_HTTP_ERROR_PA(_client_id, "Failed to send request");

            // Create error response
            auto error_response = create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "Failed to send HTTP/2 request");

            context->callback(std::move(error_response));
            _failed_requests++;
        }
    }
    arm_request_timeout();
}

void
Client::handle_connection_success() {
    LOG_HTTP_INFO_PA(_client_id, "HTTP/2 connection established successfully");

    _is_connected                        = true;
    _is_connecting                       = false;
    _handshake_completed                 = true;
    _received_graceful_goaway            = false;
    _preserve_pending_on_next_disconnect = false;
    this->setTimeout(qb::duration::zero());

    auto callbacks = std::move(_connection_callbacks);
    _connection_callbacks.clear();
    for (auto &callback : callbacks) {
        if (callback) {
            callback(true, "");
        }
    }

    // Process any pending requests
    process_pending_requests();
}

void
Client::handle_connection_failure(const std::string &error_message) {
    LOG_HTTP_ERROR_PA(_client_id, "Connection failed: " << error_message);

    _is_connected                        = false;
    _is_connecting                       = false;
    _handshake_completed                 = false;
    _received_graceful_goaway            = false;
    _preserve_pending_on_next_disconnect = false;
    _h2_protocol                         = nullptr;

    auto callbacks = std::move(_connection_callbacks);
    _connection_callbacks.clear();
    for (auto &callback : callbacks) {
        if (callback) {
            callback(false, error_message);
        }
    }

    // Fail all pending requests
    fail_all_requests("Connection failed: " + error_message);

    // Reconnect only if failure callbacks queued fresh work.
    if (_auto_reconnect && has_pending_or_active_work()) {
        attempt_reconnection();
    }
}

void
Client::complete_request(uint32_t stream_id, qb::http::Response response) {
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

    if (_received_graceful_goaway) {
        finish_graceful_goaway_if_drained();
    } else {
        process_pending_requests();
    }
    arm_request_timeout();
}

void
Client::fail_request(uint32_t stream_id, const std::string &error_message, qb::http::status status) {
    auto it = _active_requests.find(stream_id);
    if (it == _active_requests.end() || !it->second || it->second->stream_id != stream_id) {
        it = std::find_if(_active_requests.begin(), _active_requests.end(),
                          [stream_id](const auto &entry) { return entry.second && entry.second->stream_id == stream_id; });
    }
    if (it == _active_requests.end()) {
        LOG_HTTP_WARN_PA(_client_id, "Tried to fail unknown stream " << stream_id);
        return;
    }

    auto context = std::move(it->second);
    _active_requests.erase(it);

    LOG_HTTP_WARN_PA(_client_id, "Request failed (stream: " << stream_id << "): " << error_message);

    _failed_requests++;

    auto error_response = create_error_response(status, error_message);

    context->callback(std::move(error_response));

    finish_graceful_goaway_if_drained();
    arm_request_timeout();
}

void
Client::fail_active_requests_after_goaway(uint32_t last_stream_id, const std::string &error_message) {
    qb::unordered_map<uint32_t, std::unique_ptr<RequestContext>> requests_to_fail;
    for (auto it = _active_requests.begin(); it != _active_requests.end();) {
        const auto &context = it->second;
        if (context && context->stream_id > last_stream_id) {
            requests_to_fail.emplace(it->first, std::move(it->second));
            it = _active_requests.erase(it);
        } else {
            ++it;
        }
    }

    for (auto &[request_id, context] : requests_to_fail) {
        (void) request_id;
        ++_failed_requests;
        auto error_response = create_error_response(qb::http::status::SERVICE_UNAVAILABLE, error_message);
        context->callback(std::move(error_response));
    }
    arm_request_timeout();
}

void
Client::finish_graceful_goaway_if_drained() {
    if (!_received_graceful_goaway || !_active_requests.empty()) {
        return;
    }

    LOG_HTTP_INFO_PA(_client_id, "Graceful GOAWAY drain complete");

    _received_graceful_goaway = false;
    _is_connected             = false;
    _is_connecting            = false;
    _handshake_completed      = false;
    _h2_protocol              = nullptr;

    if (!_pending_requests.empty() && _auto_reconnect) {
        _preserve_pending_on_next_disconnect = true;
        BaseTcpClient::disconnect();
        return;
    }

    if (!_pending_requests.empty()) {
        fail_all_requests("Server sent GOAWAY and automatic reconnection is disabled");
    }

    _preserve_pending_on_next_disconnect = true;
    BaseTcpClient::disconnect();
}

void
Client::fail_all_requests(const std::string &error_message) {
    LOG_HTTP_WARN_PA(_client_id, "Failing all requests: " << error_message);

    // Reentrancy-safe draining: user callbacks may enqueue new requests/batches.
    // We move current work out before invoking any callback so newly queued work
    // is not lost or invalidated by this failure pass.
    qb::unordered_map<uint32_t, std::unique_ptr<RequestContext>>      active_requests_to_fail;
    std::deque<std::unique_ptr<RequestContext>>                       pending_requests_to_fail;
    qb::unordered_map<uint64_t, std::unique_ptr<BatchRequestContext>> active_batches_to_fail;
    active_requests_to_fail.swap(_active_requests);
    pending_requests_to_fail.swap(_pending_requests);
    active_batches_to_fail.swap(_active_batches);

    // Fail active requests
    for (auto &[stream_id, context] : active_requests_to_fail) {
        _failed_requests++;

        auto error_response = create_error_response(qb::http::status::SERVICE_UNAVAILABLE, error_message);

        context->callback(std::move(error_response));
    }

    // Fail pending requests
    while (!pending_requests_to_fail.empty()) {
        auto context = std::move(pending_requests_to_fail.front());
        pending_requests_to_fail.pop_front();

        _failed_requests++;

        auto error_response = create_error_response(qb::http::status::SERVICE_UNAVAILABLE, error_message);

        context->callback(std::move(error_response));
    }

    // Fail incomplete batches
    for (auto &[batch_id, batch_context] : active_batches_to_fail) {
        if (!batch_context->all_completed) {
            LOG_HTTP_WARN_PA(_client_id, "Failing incomplete batch " << batch_id);

            // Fill remaining responses with errors
            for (size_t i = 0; i < batch_context->responses.size(); ++i) {
                if (batch_context->responses[i].status().code() == 0) { // Not set yet
                    batch_context->responses[i] = create_error_response(qb::http::status::SERVICE_UNAVAILABLE, error_message);
                }
            }

            batch_context->callback(std::move(batch_context->responses));
        }
    }
    arm_request_timeout();
}

void
Client::check_request_timeouts() {
    if (_request_timeout <= qb::duration::zero()) {
        arm_request_timeout();
        return;
    }
    auto       now              = std::chrono::steady_clock::now();
    const auto timeout_duration = _request_timeout;

    // Check active requests for timeouts
    std::vector<uint32_t> timed_out_streams;

    for (const auto &entry : _active_requests) {
        auto const &context = entry.second;
        if (now - context->created_at >= timeout_duration) {
            timed_out_streams.push_back(context->stream_id);
        }
    }

    for (uint32_t stream_id : timed_out_streams) {
        fail_request(stream_id, "Request timeout", qb::http::status::REQUEST_TIMEOUT);
    }

    // Check pending requests for timeouts
    std::deque<std::unique_ptr<RequestContext>> non_timed_out_requests;

    while (!_pending_requests.empty()) {
        auto context = std::move(_pending_requests.front());
        _pending_requests.pop_front();

        if (now - context->created_at >= timeout_duration) {
            LOG_HTTP_WARN_PA(_client_id, "Pending request timed out");
            _failed_requests++;

            auto error_response = create_error_response(qb::http::status::REQUEST_TIMEOUT, "Request timeout while pending");

            context->callback(std::move(error_response));
        } else {
            non_timed_out_requests.push_back(std::move(context));
        }
    }

    _pending_requests = std::move(non_timed_out_requests);
    arm_request_timeout();
}

bool
Client::has_pending_or_active_work() const noexcept {
    return !_pending_requests.empty() || !_active_requests.empty();
}

void
Client::arm_request_timeout() {
    const auto   now          = std::chrono::steady_clock::now();
    bool         has_deadline = false;
    qb::duration delay        = qb::duration::max();

    const auto update_delay = [&](std::chrono::steady_clock::time_point started_at, qb::duration timeout) {
        if (timeout <= qb::duration::zero()) {
            return;
        }
        const auto         elapsed   = std::chrono::duration_cast<qb::duration>(now - started_at);
        const qb::duration remaining = timeout - elapsed;
        delay                        = std::min(delay, std::max(qb::duration(std::chrono::microseconds(1)), remaining));
        has_deadline                 = true;
    };

    if (_is_connecting && !_handshake_completed) {
        update_delay(_connect_started_at, _connect_timeout);
    }

    if (_request_timeout > qb::duration::zero()) {
        for (const auto &context : _pending_requests) {
            if (context) {
                update_delay(context->created_at, _request_timeout);
            }
        }
        for (const auto &[stream_id, context] : _active_requests) {
            (void) stream_id;
            if (context) {
                update_delay(context->created_at, _request_timeout);
            }
        }
    }

    if (!has_deadline) {
        this->setTimeout(qb::duration::zero());
        return;
    }

    this->setTimeout(delay);
}

bool
Client::connect_deadline_expired(std::chrono::steady_clock::time_point now) const noexcept {
    return _is_connecting && !_handshake_completed && _connect_timeout > qb::duration::zero() && now - _connect_started_at >= _connect_timeout;
}

void
Client::attempt_reconnection() {
    if (_is_connecting || _is_connected) {
        return;
    }

    LOG_HTTP_INFO_PA(_client_id, "Attempting automatic reconnection");

    // Add a small delay before reconnecting
    // In a real implementation, you might want exponential backoff
    connect(nullptr);
}

qb::http::Response
Client::create_error_response(qb::http::status status, const std::string &message) {
    qb::http::Response response;
    response.status() = status;
    response.body()   = message;
    response.add_header("content-type", "text/plain");
    response.add_header("content-length", std::to_string(message.length()));
    return response;
}

// Event handlers for qb-io framework

void
Client::on(qb::io::async::event::handshake &&) {
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

void
Client::on(qb::http::Response response, uint64_t app_request_id) {
    LOG_HTTP_DEBUG_PA(_client_id, "Received HTTP response (app_id: " << app_request_id << ")");
    complete_request(static_cast<uint32_t>(app_request_id), std::move(response));
}

void
Client::on(const qb::protocol::http2::Http2StreamErrorEvent &event) {
    LOG_HTTP_WARN_PA(_client_id, "HTTP/2 stream error on stream " << event.stream_id << ": " << event.message);
    fail_request(event.stream_id, "Stream error: " + event.message);
}

void
Client::on(const qb::protocol::http2::Http2GoAwayEvent &event) {
    LOG_HTTP_WARN_PA(_client_id, "Received GOAWAY frame: " << event.debug_data);

    std::string error_msg = "Server sent GOAWAY: " + event.debug_data;
    if (event.error_code == qb::protocol::http2::ErrorCode::NO_ERROR) {
        _received_graceful_goaway = true;
        fail_active_requests_after_goaway(event.last_stream_id, error_msg);
        finish_graceful_goaway_if_drained();
        return;
    }

    fail_all_requests(error_msg);
    disconnect();
}

void
Client::on(const qb::protocol::http2::Http2PushPromiseEvent &event) {
    LOG_HTTP_INFO_PA(_client_id, "Received PUSH_PROMISE for stream " << event.promised_stream_id);

    // Auto-reject server push by default
    if (_h2_protocol) {
        _h2_protocol->application_reject_push(event.promised_stream_id);
    }
}

void
Client::on(const qb::protocol::http2::Http2ConnectionErrorEvent &event) {
    LOG_HTTP_ERROR_PA(_client_id, "HTTP/2 connection error: " << event.message);

    std::string error_msg = "Connection error: " + event.message;
    fail_all_requests(error_msg);

    disconnect();

    if (_auto_reconnect && has_pending_or_active_work()) {
        attempt_reconnection();
    }
}

void
Client::on(qb::io::async::event::timeout const &) {
    const auto now = std::chrono::steady_clock::now();

    check_request_timeouts();

    if (connect_deadline_expired(now)) {
        LOG_HTTP_WARN_PA(_client_id, "Connection timeout");
        handle_connection_failure("Connection timeout");
        return;
    }

    arm_request_timeout();
}

void
Client::on(qb::io::async::event::disconnected const &event) {
    LOG_HTTP_INFO_PA(_client_id, "Disconnected (reason: " << event.reason << ")");

    std::string error_msg = "Connection lost";
    if (event.reason != 0) {
        error_msg += " (reason: " + std::to_string(event.reason) + ")";
    }

    if (_is_connecting && !_connection_callbacks.empty()) {
        auto callbacks = std::move(_connection_callbacks);
        _connection_callbacks.clear();
        for (auto &callback : callbacks) {
            if (callback) {
                callback(false, error_msg);
            }
        }
    }

    _is_connected        = false;
    _is_connecting       = false;
    _handshake_completed = false;
    _h2_protocol         = nullptr;

    if (_preserve_pending_on_next_disconnect) {
        _preserve_pending_on_next_disconnect = false;
        if (!_active_requests.empty()) {
            fail_all_requests(error_msg);
        }
    } else {
        fail_all_requests(error_msg);
    }

    if (_auto_reconnect && has_pending_or_active_work()) {
        attempt_reconnection();
    }
}

void
Client::on(qb::io::async::event::dispose const &) {
    LOG_HTTP_DEBUG_PA(_client_id, "Client disposal event");

    fail_all_requests("Client disposed");

    _is_connected                        = false;
    _is_connecting                       = false;
    _handshake_completed                 = false;
    _received_graceful_goaway            = false;
    _preserve_pending_on_next_disconnect = false;
    _h2_protocol                         = nullptr;
}

// Factory functions

std::shared_ptr<Client>
make_client(const std::string &base_uri) {
    return std::make_shared<Client>(base_uri);
}

std::shared_ptr<Client>
make_client(const qb::io::uri &uri) {
    return std::make_shared<Client>(uri);
}

// ---------------------------------------------------------------------------
// Coroutine overloads
//
// Each overload wraps the callback-based counterpart inside an
// `async::awaiter<T>`. They don't re-implement any protocol logic &mdash;
// they just bridge the existing callback machinery to a coroutine-friendly
// return value, exactly like `qbm/redis::redis_awaiter` and
// `qbm/pgsql::pg_reply_awaiter` do.
// ---------------------------------------------------------------------------

qb::http::async::awaiter<ConnectResult>
Client::connect() {
    auto weak_self = weak_from_this();
    return qb::http::async::make_awaiter<ConnectResult>([weak_self](std::function<void(ConnectResult &&)> complete) mutable {
        auto self = weak_self.lock();
        if (!self) {
            complete(ConnectResult{false, "HTTP/2 client no longer available"});
            return;
        }
        if (!self->connect([complete = std::move(complete)](bool ok, const std::string &err) mutable { complete(ConnectResult{ok, err}); })) {
            if (self->is_connected()) {
                complete(ConnectResult{true, ""});
            } else if (self->is_connecting()) {
                complete(ConnectResult{false, "Connection already in progress"});
            } else {
                complete(ConnectResult{false, "Unable to start connection"});
            }
        }
    });
}

qb::http::async::awaiter<qb::http::Response>
Client::push_request(qb::http::Request request) {
    auto weak_self = weak_from_this();
    return qb::http::async::make_awaiter<qb::http::Response>(
        [weak_self, req = std::move(request)](std::function<void(qb::http::Response &&)> complete) mutable {
            auto self = weak_self.lock();
            if (!self) {
                qb::http::Response error_response;
                error_response.status() = qb::http::status::SERVICE_UNAVAILABLE;
                error_response.body()   = "HTTP/2 client no longer available";
                error_response.add_header("content-type", "text/plain");
                error_response.add_header("content-length", std::to_string(error_response.body().raw().size()));
                complete(std::move(error_response));
                return;
            }
            self->push_request(std::move(req),
                               [complete = std::move(complete)](qb::http::Response response) mutable { complete(std::move(response)); });
        });
}

qb::http::async::awaiter<std::vector<qb::http::Response>>
Client::push_requests(std::vector<qb::http::Request> requests) {
    auto weak_self = weak_from_this();
    return qb::http::async::make_awaiter<std::vector<qb::http::Response>>(
        [weak_self, reqs = std::move(requests)](std::function<void(std::vector<qb::http::Response> &&)> complete) mutable {
            auto self = weak_self.lock();
            if (!self) {
                complete({});
                return;
            }
            self->push_requests(std::move(reqs), [complete = std::move(complete)](std::vector<qb::http::Response> responses) mutable {
                complete(std::move(responses));
            });
        });
}

} // namespace qb::http2

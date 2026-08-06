/**
 * @file qbm/http/2/client.h
 * @brief HTTP/2 client interface for qb-io framework
 *
 * This file provides a high-level HTTP/2 client interface built on top of
 * the qb-io asynchronous framework. It includes:
 *
 * - Modern C++ HTTP/2 client with callback-based API
 * - Connection management with automatic reconnection support
 * - Request multiplexing and stream management
 * - Batch request processing for improved efficiency
 * - Configurable timeouts for connections and requests
 * - Response and error callback handling
 * - Integration with HTTP/1.1 request/response objects
 * - Factory functions for easy client creation
 *
 * @code
 * // Example HTTP/2 client usage:
 * auto client = qb::http2::make_client("https://api.example.com");
 * client->connect([](bool success) {
 *     if (success) {
 *         qb::http::Request req("https://api.example.com/data");
 *         client->push_request(std::move(req), [](qb::http::Response res) {
 *             // Handle response
 *         });
 *     }
 * });
 * @endcode
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

// HTTP/2 is TLS-only here: qb::http2::Client derives from
// qb::io::async::tcp::client<Client, qb::io::transport::stcp>, and `stcp` -- the SSL/TLS
// transport -- only exists when qb was built with OpenSSL. Without this guard an SSL-off build
// that includes this header DIRECTLY got a raw template diagnostic in the middle of a base-clause,
//     2/client.h:144:68: error: no member named 'stcp' in namespace 'qb::io::transport'
// naming neither SSL nor HTTP/2. It never fired through the umbrella (qbm/http/http.h wraps
// ./2/http2.h in #ifdef QB_HAS_SSL) which is why the whole SSL-off consumer suite stayed green;
// the installed-header sweep is what reaches it. Eleven sibling headers already self-diagnose
// this way -- ws/ws.h, auth.h, the HTTP/3 set -- and these two were the exceptions.
#ifndef QB_HAS_SSL
#error "HTTP/2 requires OpenSSL crypto library (qb::io::transport::stcp)"
#endif

#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <qb/io/async.h>
#include <qb/io/protocol/handshake.h>
#include <qb/io/uri.h>
#include <qb/system/container/unordered_map.h>
#include <qb/uuid.h>

#include "../coro.h"
#include "../logger.h"
#include "../request.h"
#include "../response.h"
#include "protocol/client.h"

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
using ConnectionCallback = std::function<void(bool connected, const std::string &error_message)>;

/**
 * @brief Result returned by the coroutine-style `connect()` awaiter.
 *
 * Boolean-convertible so that call sites read naturally:
 * @code
 * if (!co_await client->connect()) co_return;   // ok on failure
 * @endcode
 */
struct ConnectResult {
    bool        ok{false};
    std::string error_message;

    explicit
    operator bool() const noexcept {
        return ok;
    }
};

/**
 * @brief Request context for tracking pending requests
 */
struct RequestContext {
    qb::http::Request                     request;
    ResponseCallback                      callback;
    std::chrono::steady_clock::time_point created_at;
    uint32_t                              stream_id = 0;
    bool                                  completed = false;
};

/**
 * @brief Batch request context for tracking multiple requests
 */
struct BatchRequestContext {
    std::vector<qb::http::Request>        requests;
    BatchResponseCallback                 callback;
    std::vector<qb::http::Response>       responses;
    std::chrono::steady_clock::time_point created_at;
    qb::unordered_map<uint32_t, size_t>   stream_to_index; // stream_id -> request index
    size_t                                completed_count = 0;
    bool                                  all_completed   = false;
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
class Client
    : public std::enable_shared_from_this<Client>
    , public qb::io::async::tcp::client<Client, qb::io::transport::stcp>
    , public qb::io::use<Client>::timeout {
public:
    using H2Protocol        = qb::protocol::http2::ClientHttp2Protocol<Client>;
    using HandshakeProtocol = qb::io::protocol::handshake<Client>;
    using BaseTcpClient     = qb::io::async::tcp::client<Client, qb::io::transport::stcp>;

private:
    // Connection state
    qb::io::uri                           _base_uri;
    qb::uuid                              _client_id;
    std::string                           _host;
    uint16_t                              _port;
    bool                                  _is_connected                        = false;
    bool                                  _is_connecting                       = false;
    bool                                  _handshake_completed                 = false;
    bool                                  _received_graceful_goaway            = false;
    bool                                  _preserve_pending_on_next_disconnect = false;
    std::chrono::steady_clock::time_point _connect_started_at{};

    // Protocol handlers
    H2Protocol *_h2_protocol = nullptr;

    // Request management
    std::deque<std::unique_ptr<RequestContext>>                       _pending_requests;
    qb::unordered_map<uint32_t, std::unique_ptr<RequestContext>>      _active_requests;
    qb::unordered_map<uint64_t, std::unique_ptr<BatchRequestContext>> _active_batches;
    uint64_t                                                          _next_batch_id = 1;

    // Configuration
    qb::duration _connect_timeout        = std::chrono::seconds(30);
    qb::duration _request_timeout        = std::chrono::seconds(60);
    bool         _verify_peer            = true; /**< Verify the server TLS certificate (h2 is TLS-only). */
    size_t       _max_concurrent_streams = 100;
    size_t       _max_pending_requests =
        1024; /**< Bound on outstanding (pending + active) requests; rejects with 503 past this (DoS guard, matches http1/http3). */
    bool _auto_reconnect = true;

    // Callbacks
    std::vector<ConnectionCallback> _connection_callbacks;

    // Statistics
    uint64_t _total_requests{0};
    uint64_t _successful_requests{0};
    uint64_t _failed_requests{0};

public:
    /**
     * @brief Construct HTTP/2 client
     * @param base_uri Base URI for the connection (scheme, host, port)
     */
    explicit Client(const std::string &base_uri);

    /**
     * @brief Construct HTTP/2 client with URI object
     * @param uri Base URI for the connection
     */
    explicit Client(const qb::io::uri &uri);

    ~Client();

    // Disable copy and move (base class doesn't support them)
    Client(const Client &)            = delete;
    Client &operator=(const Client &) = delete;
    Client(Client &&)                 = delete;
    Client &operator=(Client &&)      = delete;

    /**
     * @brief Connect to the server (callback-style).
     * @param callback Callback invoked on success or failure. Pass `nullptr`
     *                 for fire-and-forget (you will still be able to
     *                 `push_request` before connection completes; they will
     *                 be queued and flushed on handshake).
     * @return true if connection attempt started, false if already connected/connecting.
     *
     * @note The default argument is intentionally removed (compared to pre-coroutine
     *       versions of this API) so that the coroutine overload `connect()` is
     *       unambiguous. Call sites that want the old fire-and-forget semantic
     *       should write `connect(nullptr)`.
     */
    bool connect(ConnectionCallback callback);

    /**
     * @brief Connect to the server (coroutine-style).
     *
     * Yields a `ConnectResult` once the HTTP/2 handshake is complete (or
     * failed). Usage:
     *
     * @code
     * if (!co_await client->connect()) {
     *     LOG_ERROR("HTTP/2 connect failed");
     *     co_return;
     * }
     * @endcode
     *
     * Blocking equivalent (tests, main):
     * @code
     * auto r = qb::http::run_sync(client->connect());
     * @endcode
     *
     * @return Awaitable yielding a `ConnectResult`.
     */
    [[nodiscard]] qb::http::async::awaiter<ConnectResult> connect();

    /**
     * @brief Disconnect from server
     */
    void disconnect();

    /**
     * @brief Check if client is connected
     * @return true if connected and ready for requests
     */
    [[nodiscard]] bool
    is_connected() const noexcept {
        return _is_connected && _handshake_completed;
    }

    /**
     * @brief Check if client is connecting
     * @return true if connection attempt in progress
     */
    [[nodiscard]] bool
    is_connecting() const noexcept {
        return _is_connecting;
    }

    /**
     * @brief Send a single HTTP request (callback-style).
     * @param request HTTP request to send
     * @param callback Callback to handle the response
     * @return true if request was queued successfully
     */
    bool push_request(qb::http::Request request, ResponseCallback callback);

    /**
     * @brief Send a single HTTP request (coroutine-style).
     *
     * The returned awaitable yields the `qb::http::Response` when available.
     * Connection is established lazily &mdash; you can `co_await` without
     * calling `connect()` first.
     *
     * @code
     * auto response = co_await client->push_request(std::move(req));
     * @endcode
     *
     * @return Awaitable yielding a `qb::http::Response`.
     */
    [[nodiscard]] qb::http::async::awaiter<qb::http::Response> push_request(qb::http::Request request);

    /**
     * @brief Send multiple HTTP requests as a batch (callback-style).
     * @param requests Vector of HTTP requests to send
     * @param callback Callback to handle all responses (in same order as requests)
     * @return true if batch was queued successfully
     */
    bool push_requests(std::vector<qb::http::Request> requests, BatchResponseCallback callback);

    /**
     * @brief Send multiple HTTP requests as a batch (coroutine-style).
     *
     * The requests are sent on separate HTTP/2 streams concurrently; the
     * returned awaitable yields when all responses are in (order preserved).
     *
     * @code
     * auto responses = co_await client->push_requests(std::move(reqs));
     * @endcode
     *
     * @return Awaitable yielding a `std::vector<qb::http::Response>`.
     */
    [[nodiscard]] qb::http::async::awaiter<std::vector<qb::http::Response>> push_requests(std::vector<qb::http::Request> requests);

    /**
     * @brief Set connection timeout
     * @param timeout_seconds Timeout in seconds
     */
    void
    set_connect_timeout(qb::duration timeout) {
        _connect_timeout = timeout;
    }

    /**
     * @brief Enable/disable TLS server certificate verification.
     * @param value `true` (default) verifies chain + hostname; `false` disables it
     *              (trusted/self-signed endpoints only). Set before connecting.
     */
    void
    set_verify_peer(bool value) noexcept {
        _verify_peer = value;
    }
    [[nodiscard]] bool
    verify_peer() const noexcept {
        return _verify_peer;
    }

    /**
     * @brief Set request timeout
     * @param timeout_seconds Timeout in seconds
     */
    void
    set_request_timeout(qb::duration timeout) {
        _request_timeout = timeout;
    }

    /**
     * @brief Set maximum concurrent streams
     * @param max_streams Maximum number of concurrent streams
     */
    void
    set_max_concurrent_streams(size_t max_streams) {
        _max_concurrent_streams = max_streams;
    }

    /**
     * @brief Set the maximum number of outstanding (pending + active) requests.
     * Past this bound `push_request()` / `push_requests()` reject with `503 Service Unavailable`
     * instead of letting the pending queue grow without limit (DoS guard).
     * @param value Maximum outstanding requests (default 1024).
     */
    void
    set_max_pending_requests(size_t value) noexcept {
        _max_pending_requests = value;
    }

    /**
     * @brief Enable/disable automatic reconnection
     * @param enable Whether to automatically reconnect on connection loss
     */
    void
    set_auto_reconnect(bool enable) {
        _auto_reconnect = enable;
    }

    /**
     * @brief Get client statistics
     * @return Tuple of (total_requests, successful_requests, failed_requests)
     */
    [[nodiscard]] std::tuple<uint64_t, uint64_t, uint64_t>
    get_stats() const noexcept {
        return {_total_requests, _successful_requests, _failed_requests};
    }

    /**
     * @brief Get number of active requests
     * @return Number of requests currently being processed
     */
    [[nodiscard]] size_t
    get_active_request_count() const noexcept {
        return _active_requests.size();
    }

    /**
     * @brief Get base URI
     * @return Base URI for this client
     */
    [[nodiscard]] const qb::io::uri &
    get_base_uri() const noexcept {
        return _base_uri;
    }

    // Event handlers for qb-io framework
    void on(qb::io::async::event::handshake &&);
    void on(qb::http::Response response, uint64_t app_request_id);
    void on(const qb::protocol::http2::Http2StreamErrorEvent &event);
    void on(const qb::protocol::http2::Http2GoAwayEvent &event);
    void on(const qb::protocol::http2::Http2PushPromiseEvent &event);
    void on(const qb::protocol::http2::Http2ConnectionErrorEvent &event);
    void on(qb::io::async::event::timeout const &);
    void on(qb::io::async::event::disconnected const &event);
    void on(qb::io::async::event::dispose const &);

private:
    /**
     * @brief Initialize client from URI
     * @param uri URI to parse
     */
    void initialize_from_uri(const qb::io::uri &uri);

    /**
     * @brief Start connection attempt
     */
    void start_connection();

    /**
     * @brief Normalize relative request URI against the client's HTTPS base URI.
     */
    void ensure_absolute_uri(qb::http::Request &request);

    /**
     * @brief Normalize and validate a request before it can be queued.
     */
    [[nodiscard]] std::optional<qb::http::Response> prepare_request(qb::http::Request &request);

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
    void handle_connection_failure(const std::string &error_message);

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
    void fail_request(uint32_t stream_id, const std::string &error_message, qb::http::status status = qb::http::status::BAD_GATEWAY);

    /**
     * @brief Fail active streams that the peer explicitly did not process in GOAWAY.
     */
    void fail_active_requests_after_goaway(uint32_t last_stream_id, const std::string &error_message);

    /**
     * @brief Finish a graceful GOAWAY drain once accepted streams are complete.
     */
    void finish_graceful_goaway_if_drained();

    /**
     * @brief Fail all active requests
     * @param error_message Error description
     */
    void fail_all_requests(const std::string &error_message);

    /**
     * @brief Check and handle request timeouts
     */
    void check_request_timeouts();

    /**
     * @brief Arm a one-shot timeout for the earliest connect, pending, or active request deadline.
     */
    void arm_request_timeout();

    /**
     * @brief Returns true when the current connection attempt exceeded its deadline.
     */
    [[nodiscard]] bool connect_deadline_expired(std::chrono::steady_clock::time_point now) const noexcept;

    /**
     * @brief Returns true when there is outstanding client work tied to the current connection.
     */
    [[nodiscard]] bool has_pending_or_active_work() const noexcept;

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
    qb::http::Response create_error_response(qb::http::status status, const std::string &message);
};
using client = Client;

/**
 * @brief Create a shared HTTP/2 client
 * @param base_uri Base URI for the connection
 * @return Shared pointer to HTTP/2 client
 */
std::shared_ptr<Client> make_client(const std::string &base_uri);

/**
 * @brief Create a shared HTTP/2 client with URI object
 * @param uri Base URI for the connection
 * @return Shared pointer to HTTP/2 client
 */
std::shared_ptr<Client> make_client(const qb::io::uri &uri);

} // namespace qb::http2

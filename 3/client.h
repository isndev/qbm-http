/**
 * @file qbm/http/3/client.h
 * @brief HTTP/3 client API.
 *
 * Declares the persistent, single-origin HTTP/3 client built on top of the
 * qb-io QUIC endpoint. The client multiplexes requests over a single QUIC
 * connection (subject to the peer's concurrent-stream limit), queues requests
 * while connecting, supports both callback and coroutine-awaiter styles,
 * batches requests, enforces connect/request timeouts, and optionally
 * reconnects automatically when work is outstanding.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#ifndef QBM_HTTP_HAS_HTTP3
#error "HTTP/3 support is not enabled. Build qbm/http with QBM_HTTP_HAS_HTTP3."
#endif

#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <qb/io/async.h>
#include <qb/io/async/quic/endpoint.h>
#include <qb/system/container/unordered_map.h>
#include <qb/uuid.h>

#include "../coro.h"
#include "../request.h"
#include "../response.h"
#include "protocol/connection.h"

namespace qb::http3 {

/// Invoked with the completed (or synthesized error) response for one request.
using ResponseCallback = std::function<void(qb::http::Response)>;
/// Invoked once with all responses when a batch of requests completes.
using BatchResponseCallback = std::function<void(std::vector<qb::http::Response>)>;
/// Invoked on connection outcome: @p connected, and @p error_message if failed.
using ConnectionCallback = std::function<void(bool connected, const std::string &error_message)>;
/// Opaque per-request identifier handed out by push_request_with_id().
using request_id = std::uint64_t;

/**
 * @brief Result of an awaited connect() attempt.
 *
 * Convertible to @c bool so it can be tested directly; @c true iff the
 * connection succeeded.
 */
struct ConnectResult {
    bool        ok{false};     ///< Whether the connection succeeded.
    std::string error_message; ///< Failure reason when @c ok is false.

    /// @return @c true iff the connection succeeded.
    explicit
    operator bool() const noexcept {
        return ok;
    }
};

/**
 * @brief Internal bookkeeping for a single in-flight or queued request.
 */
struct RequestContext {
    qb::http::Request                     request;
    ResponseCallback                      callback;
    std::chrono::steady_clock::time_point created_at;
    qb::http3::request_id                 request_id = 0;
    std::uint64_t                         stream_id  = 0;
    std::uint64_t                         batch_id   = 0;
};

/**
 * @brief Internal bookkeeping for a batch of requests submitted together.
 *
 * Responses are filled in by index as each member request completes; the
 * @c callback fires once @c completed_count reaches @c responses.size().
 */
struct BatchRequestContext {
    BatchResponseCallback           callback;            ///< Fired once when the whole batch finishes.
    std::vector<qb::http::Response> responses;           ///< Per-request responses, indexed by submission order.
    std::vector<bool>               completed;           ///< Per-request completion flags.
    std::size_t                     completed_count = 0; ///< Number of requests completed so far.
};

/**
 * @brief Persistent single-origin HTTP/3 client over a QUIC connection.
 *
 * A Client owns one QUIC connection to a single @c https origin and
 * multiplexes requests over it. Requests issued before the connection is
 * established are queued and flushed on connect; concurrency is bounded by the
 * peer's stream limit (see set_max_concurrent_streams()). Both callback-based
 * and coroutine-awaiter APIs are provided. The client must be owned via
 * @c std::shared_ptr (it derives from @c std::enable_shared_from_this) so that
 * deferred timeout/connect callbacks can safely re-acquire it; use
 * make_client() to construct one.
 *
 * @note Non-copyable. Only same-origin requests are accepted.
 */
class Client
    : public std::enable_shared_from_this<Client>
    , public qb::io::async::quic::endpoint {
public:
    using h3_connection = qb::protocol::http3::connection<Client>;

private:
    qb::io::uri _base_uri;
    qb::uuid    _client_id;
    std::string _host;
    bool        _is_connected    = false;
    bool        _is_connecting   = false;
    bool        _h3_ready        = false;
    bool        _remote_shutdown = false;

    // Reentrancy guard for HTTP/3 reads. nghttp3_conn_read_stream2 (driven from
    // dispatch(stream_data)) runs response callbacks that can synchronously fail the
    // connection — a send larger than the QUIC TX cap makes the backend queue a close and
    // reentrantly delivers dispatch(connection_closed). Tearing _h3 down there would call
    // nghttp3_conn_del while the outer read is still on the stack (use-after-free), and fire
    // user callbacks reentrantly. While _read_depth > 0 the teardown is DEFERRED into
    // _deferred_close and executed once the outermost read returns.
    int                        _read_depth = 0;
    std::optional<std::string> _deferred_close;

    std::unique_ptr<h3_connection>                                         _h3;
    std::deque<std::unique_ptr<RequestContext>>                            _pending_requests;
    qb::unordered_map<std::uint64_t, std::unique_ptr<RequestContext>>      _active_requests;
    qb::unordered_map<std::uint64_t, std::unique_ptr<BatchRequestContext>> _active_batches;
    std::uint64_t                                                          _next_request_id = 1;
    std::uint64_t                                                          _next_batch_id   = 1;

    std::size_t                     _max_concurrent_streams = 100;
    std::size_t                     _max_pending_requests   = 10000; ///< Cap on queued+active requests (bounds _pending_requests)
    std::size_t                     _max_body_size          = 64 * 1024 * 1024;
    qb::duration                    _connect_timeout        = std::chrono::seconds(30);
    qb::duration                    _request_timeout        = std::chrono::seconds(60);
    bool                            _auto_reconnect         = true;
    bool                            _verify_peer            = true;
    std::vector<ConnectionCallback> _connection_callbacks;

    std::uint64_t _total_requests      = 0;
    std::uint64_t _successful_requests = 0;
    std::uint64_t _failed_requests     = 0;

public:
    /**
     * @brief Construct a client bound to a base origin given as a string.
     * @param base_uri Base URI; must use the @c https scheme.
     * @throws std::invalid_argument if the scheme is not @c https.
     */
    explicit Client(std::string const &base_uri);
    /**
     * @brief Construct a client bound to a base origin given as a parsed URI.
     * @param uri Base URI; must use the @c https scheme.
     * @throws std::invalid_argument if the scheme is not @c https.
     */
    explicit Client(qb::io::uri const &uri);
    /// Destructor: fails all outstanding requests and tears down the connection.
    ~Client();

    Client(Client const &)            = delete;
    Client &operator=(Client const &) = delete;

    /**
     * @brief Begin connecting (if not already connected/connecting).
     * @param callback Invoked with the connection outcome; may be null.
     * @return @c true if the connection is already established or a connect
     *         attempt was started/joined; @c false if it could not be started.
     */
    bool connect(ConnectionCallback callback);
    /**
     * @brief Coroutine-awaiter variant of connect().
     * @return An awaiter resolving to the ConnectResult of the attempt.
     */
    [[nodiscard]] qb::http::async::awaiter<ConnectResult> connect();
    /// Fail all outstanding requests and close the QUIC connection.
    void disconnect();

    /// @return @c true once the QUIC connection is up and HTTP/3 is ready.
    [[nodiscard]] bool
    is_connected() const noexcept {
        return _is_connected && _h3_ready;
    }
    /// @return @c true while a connection attempt is in progress.
    [[nodiscard]] bool
    is_connecting() const noexcept {
        return _is_connecting;
    }

    /**
     * @brief Queue a request, delivering the response via @p callback.
     * @param request  Request to send (made absolute against the base origin).
     * @param callback Response handler; must be non-null.
     * @return @c true if accepted; @c false if @p callback is null.
     */
    bool push_request(qb::http::Request request, ResponseCallback callback);
    /**
     * @brief Queue a request and return its cancellation id.
     * @param request  Request to send (made absolute against the base origin).
     * @param callback Response handler; must be non-null.
     * @return The request id, or 0 if the request was rejected/failed synchronously.
     */
    [[nodiscard]] request_id push_request_with_id(qb::http::Request request, ResponseCallback callback);
    /**
     * @brief Cancel a queued or in-flight request by id.
     * @param id     Request id from push_request_with_id().
     * @param reason Reason text used in the synthesized error response.
     * @return @c true if a matching request was found and cancelled.
     */
    bool cancel_request(request_id id, std::string const &reason = "HTTP/3 request cancelled");
    /**
     * @brief Coroutine-awaiter variant of push_request().
     * @param request Request to send.
     * @return An awaiter resolving to the response (or a synthesized error).
     */
    [[nodiscard]] qb::http::async::awaiter<qb::http::Response> push_request(qb::http::Request request);
    /**
     * @brief Queue a batch of requests, delivering all responses via @p callback.
     * @param requests Requests to send; an empty batch completes immediately.
     * @param callback Batch handler; must be non-null for a non-empty batch.
     * @return @c true if accepted; @c false if @p callback is null.
     */
    bool push_requests(std::vector<qb::http::Request> requests, BatchResponseCallback callback);
    /**
     * @brief Coroutine-awaiter variant of push_requests().
     * @param requests Requests to send.
     * @return An awaiter resolving to the vector of responses.
     */
    [[nodiscard]] qb::http::async::awaiter<std::vector<qb::http::Response>> push_requests(std::vector<qb::http::Request> requests);

    /// Set the max number of concurrent request streams to keep in flight.
    void
    set_max_concurrent_streams(std::size_t value) noexcept {
        _max_concurrent_streams = value;
    }
    /// Set the maximum accepted response body size, in bytes.
    void
    set_max_body_size(std::size_t value) noexcept {
        _max_body_size = value;
    }
    /// Set the connection-establishment timeout (zero disables it).
    void
    set_connect_timeout(qb::duration value) noexcept {
        _connect_timeout = value;
    }
    /// Set the per-request timeout (zero disables it).
    void
    set_request_timeout(qb::duration value) noexcept {
        _request_timeout = value;
    }
    /// Enable/disable automatic reconnection while work is outstanding.
    void
    set_auto_reconnect(bool value) noexcept {
        _auto_reconnect = value;
    }
    /// Enable/disable TLS peer-certificate verification.
    void
    set_verify_peer(bool value) noexcept {
        _verify_peer = value;
    }

    /// @return Tuple of (total, successful, failed) request counters.
    [[nodiscard]] std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>
    get_stats() const noexcept {
        return {_total_requests, _successful_requests, _failed_requests};
    }

    /// @return Number of requests currently in flight (active streams).
    [[nodiscard]] std::size_t
    get_active_request_count() const noexcept {
        return _active_requests.size();
    }

    /// @return The configured maximum response body size, in bytes.
    [[nodiscard]] std::size_t
    max_http3_body_size() const noexcept {
        return _max_body_size;
    }
    /// @return The base origin URI this client is bound to.
    [[nodiscard]] qb::io::uri const &
    get_base_uri() const noexcept {
        return _base_uri;
    }

    // --- HTTP/3 transport hooks used by the protocol layer (h3_connection) ---

    /// Open a new unidirectional QUIC stream; @return its stream id.
    std::uint64_t open_http3_unidirectional_stream(std::uint64_t connection_id);
    /// Write @p data on @p stream_id, optionally finishing the stream (@p fin).
    void send_http3_stream_data(std::uint64_t connection_id, std::uint64_t stream_id, std::string_view data, bool fin);
    /// Grant @p bytes of additional flow-control credit on @p stream_id.
    void extend_http3_stream_credit(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t bytes);
    /// Reset (abort sending on) @p stream_id with @p app_error_code.
    void reset_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t app_error_code);
    /// Request the peer stop sending on @p stream_id with @p app_error_code.
    void stop_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t app_error_code);
    /// Close the QUIC connection with @p app_error_code and @p reason.
    void close_http3_connection(std::uint64_t connection_id, std::uint64_t app_error_code, std::string_view reason);
    /// Notification that @p bytes on @p stream_id have been acknowledged (no-op).
    void on_http3_stream_acked(std::uint64_t stream_id, std::uint64_t bytes);
    /// Notification that @p stream_id closed; fails the request if still active.
    void on_http3_stream_closed(std::uint64_t stream_id, std::uint64_t app_error_code);
    /// Notification of graceful server shutdown; fails all pending requests.
    void on_http3_shutdown(std::uint64_t connection_id, std::uint64_t last_stream_id);
    /// Deliver a completed @p response for @p stream_id to its request callback.
    void on_http3_response(std::uint64_t stream_id, qb::http::Response response);

protected:
    /// QUIC: connection established; validate ALPN and flush pending requests.
    void dispatch(qb::io::async::quic::event::connected const &ev) override;
    /// QUIC: connection closed; fail outstanding work and maybe reconnect.
    void dispatch(qb::io::async::quic::event::connection_closed const &ev) override;
    /// QUIC: inbound stream data; forward to the HTTP/3 connection parser.
    void dispatch(qb::io::async::quic::event::stream_data const &ev) override;
    /// QUIC: stream data acknowledged; forward the ack offset to HTTP/3.
    void dispatch(qb::io::async::quic::event::stream_data_acked const &ev) override;
    /// QUIC: stream closed; route to on_http3_stream_closed().
    void dispatch(qb::io::async::quic::event::stream_closed const &ev) override;

private:
    /// Validate scheme and capture base URI/host from @p uri.
    void initialize_from_uri(qb::io::uri const &uri);
    /// Rewrite a relative request URI to an absolute one against the base origin.
    void ensure_absolute_uri(qb::http::Request &request);
    /// Validate/normalize @p request; @return an error response if rejected.
    [[nodiscard]] std::optional<qb::http::Response> prepare_request(qb::http::Request &request);
    /// Submit as many queued requests as the concurrency limit allows.
    void process_pending_requests();
    /// Mark the connection up, notify callbacks, and flush pending requests.
    void handle_connection_success(std::string const &alpn);
    /// Mark the connection down, notify callbacks, and fail all requests.
    void handle_connection_failure(std::string const &error);
    /// Fail every pending/active request and batch with @p error.
    void fail_all_requests(std::string const &error);
    /// Fail the active request on @p stream_id with @p status and @p error.
    void fail_request(std::uint64_t stream_id, std::string const &error, qb::http::status status = qb::http::status::BAD_GATEWAY);
    /// Fail the pending request with @p request_id with @p status and @p error.
    void fail_pending_request(std::uint64_t request_id, std::string const &error, qb::http::status status = qb::http::status::BAD_GATEWAY);
    /// Arm the one-shot connect-timeout callback.
    void arm_connect_timeout();
    /// Arm the per-request timeout for @p request_id.
    void arm_request_timeout(std::uint64_t request_id);
    /// (Re)schedule the request-timeout callback for @p request_id after @p delay.
    void schedule_request_timeout(std::uint64_t request_id, qb::duration delay);
    /// @return @c true if any pending request, active request, or batch remains.
    [[nodiscard]] bool has_pending_or_active_work() const noexcept;
    /// Build a text/plain error response with @p status and @p message.
    [[nodiscard]] qb::http::Response create_error_response(qb::http::status status, std::string const &message);
};

/// Convenience lowercase alias for Client.
using client = Client;

/**
 * @brief Create a shared HTTP/3 client bound to @p base_uri.
 * @param base_uri Base origin URI; must use the @c https scheme.
 * @return A @c std::shared_ptr owning the new client.
 * @throws std::invalid_argument if the scheme is not @c https.
 */
std::shared_ptr<Client> make_client(std::string const &base_uri);
/**
 * @brief Create a shared HTTP/3 client bound to @p uri.
 * @param uri Base origin URI; must use the @c https scheme.
 * @return A @c std::shared_ptr owning the new client.
 * @throws std::invalid_argument if the scheme is not @c https.
 */
std::shared_ptr<Client> make_client(qb::io::uri const &uri);

} // namespace qb::http3

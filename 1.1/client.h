/**
 * @file qbm/http/1.1/client.h
 * @brief Persistent HTTP/1.1 client API.
 *
 * This file declares `qb::http1::Client`, an asynchronous, single-threaded
 * HTTP/1.1 client built on top of qb-io. The client owns a single persistent
 * (keep-alive) connection to one origin, serializes requests over it, supports
 * automatic reconnection, request timeouts, batch requests, and both
 * callback-based and coroutine (`awaiter`) styles. Plain `http` and TLS
 * `https` targets are both supported (TLS gated on `QB_HAS_SSL`).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include <qb/io/async.h>
#include <qb/io/uri.h>
#include <qb/system/container/unordered_map.h>

#include "../coro.h"
#include "../logger.h"
#include "../request.h"
#include "../response.h"
#include "./protocol/client.h"

namespace qb::http1 {

/** @brief Callback invoked with the response (or a synthesized error response) for a single request. */
using ResponseCallback = std::function<void(qb::http::Response)>;
/** @brief Callback invoked once with all responses, in request order, when a batch completes. */
using BatchResponseCallback = std::function<void(std::vector<qb::http::Response>)>;
/** @brief Callback invoked on connection outcome: `connected` flag plus an error message on failure. */
using ConnectionCallback = std::function<void(bool connected, const std::string &error_message)>;

/**
 * @brief Result of the coroutine `connect()` overload.
 *
 * Convertible to `bool` (true when the connection succeeded) for ergonomic use
 * in `if`/`co_await` expressions.
 */
struct ConnectResult {
    bool        ok{false};     /**< `true` if the connection was established. */
    std::string error_message; /**< Human-readable reason when `ok` is `false`; empty on success. */

    /** @return `true` if the connection succeeded. */
    explicit
    operator bool() const noexcept {
        return ok;
    }
};

/**
 * @brief Internal bookkeeping for a single in-flight or pending request.
 */
struct RequestContext {
    std::uint64_t                         request_id = 0; /**< Monotonic id used to match pending timeouts. */
    qb::http::Request                     request;        /**< The prepared request to send. */
    ResponseCallback                      callback;       /**< User callback to invoke with the response. */
    std::chrono::steady_clock::time_point created_at;     /**< Enqueue time stamp. */
};

/**
 * @brief Internal bookkeeping for a batch of requests sharing one completion callback.
 */
struct BatchRequestContext {
    BatchResponseCallback           callback;            /**< Invoked once when every response has arrived. */
    std::vector<qb::http::Response> responses;           /**< Responses indexed by original request position. */
    std::size_t                     completed_count = 0; /**< Number of responses received so far. */
};

/**
 * @brief Asynchronous persistent HTTP/1.1 client bound to a single origin.
 *
 * Owns one keep-alive connection to the origin given at construction. Requests
 * are queued and sent one at a time over the connection; on a non-keep-alive
 * response, connection loss, or timeout the client (optionally) reconnects and
 * drains the queue. Must be created via `std::make_shared` / `make_client`
 * because it relies on `shared_from_this` for safe asynchronous self-reference.
 *
 * Single-threaded: all methods must run on the qb-io event loop thread that
 * owns the client.
 */
class Client : public std::enable_shared_from_this<Client> {
    class callback_scope;

    class connection_base {
    public:
        virtual ~connection_base()                                                                         = default;
        virtual void               connect(qb::io::uri const &uri, qb::duration timeout, bool verify_peer) = 0;
        virtual void               disconnect()                                                            = 0;
        virtual void               send(qb::http::Request request, qb::duration timeout)                   = 0;
        [[nodiscard]] virtual bool is_open() const noexcept                                                = 0;
    };

    template <typename Transport>
    class connection;

    qb::io::uri             _base_uri;
    std::string             _host;
    bool                    _is_connected               = false;
    bool                    _is_connecting              = false;
    bool                    _intentional_disconnect     = false;
    bool                    _reconnect_after_disconnect = false;
    std::shared_ptr<Client> _callback_self_guard;
    std::size_t             _callback_depth            = 0;
    bool                    _deferred_connection_reset = false;

    std::unique_ptr<connection_base>                                       _connection;
    std::deque<std::unique_ptr<RequestContext>>                            _pending_requests;
    std::unique_ptr<RequestContext>                                        _active_request;
    qb::unordered_map<std::uint64_t, std::unique_ptr<BatchRequestContext>> _active_batches;
    std::uint64_t                                                          _next_request_id = 1;
    std::uint64_t                                                          _next_batch_id   = 1;

    qb::duration                    _connect_timeout      = std::chrono::seconds(30);
    qb::duration                    _request_timeout      = std::chrono::seconds(60);
    std::size_t                     _max_pending_requests = 1024;
    bool                            _auto_reconnect       = true;
    bool                            _verify_peer          = true; /**< Verify the server TLS certificate (https). */
    std::vector<ConnectionCallback> _connection_callbacks;

    std::uint64_t _total_requests      = 0;
    std::uint64_t _successful_requests = 0;
    std::uint64_t _failed_requests     = 0;

public:
    /**
     * @brief Construct a client bound to the origin of @p base_uri.
     * @param base_uri Origin URI string; must use scheme `http` (or `https` when
     *                 `QB_HAS_SSL` is enabled) and carry a non-empty host.
     * @throws std::invalid_argument if the scheme is unsupported or the host is missing.
     */
    explicit Client(std::string const &base_uri);
    /**
     * @brief Construct a client bound to the origin of @p uri.
     * @param uri Origin URI; must use scheme `http` (or `https` when `QB_HAS_SSL`
     *            is enabled) and carry a non-empty host.
     * @throws std::invalid_argument if the scheme is unsupported or the host is missing.
     */
    explicit Client(qb::io::uri const &uri);
    /** @brief Disconnect and fail any outstanding requests. */
    ~Client();

    Client(Client const &)            = delete;
    Client &operator=(Client const &) = delete;

    /**
     * @brief Open (or reuse) the connection, notifying via callback.
     * @param callback Invoked with the connection outcome. If already connected,
     *                 it is invoked immediately with success; if a connection is
     *                 in progress, it is queued. May be empty.
     * @return `true` if connected or the attempt was started/queued; `false` if no
     *         attempt could be started and no callback was provided.
     */
    bool connect(ConnectionCallback callback);
    /**
     * @brief Coroutine connect.
     * @return An awaiter that resolves to a `ConnectResult` describing the outcome.
     */
    [[nodiscard]] qb::http::async::awaiter<ConnectResult> connect();
    /**
     * @brief Intentionally close the connection and fail all active/pending requests.
     *
     * Disables auto-reconnect for the current cycle; the underlying connection is
     * reset immediately, or deferred until the current user-callback scope unwinds.
     */
    void disconnect();

    /** @return `true` if a connection is currently established. */
    [[nodiscard]] bool
    is_connected() const noexcept {
        return _is_connected;
    }
    /** @return `true` if a connection attempt is in progress. */
    [[nodiscard]] bool
    is_connecting() const noexcept {
        return _is_connecting;
    }

    /**
     * @brief Queue a single request, delivering its response via callback.
     * @param request The request to send; rewritten to an absolute same-origin URI
     *                with default `Host`/`User-Agent`/`Accept-Encoding` headers.
     * @param callback Invoked with the response or a synthesized error response.
     * @return `false` if @p callback is empty or the pending-request limit is
     *         reached (the callback still fires with an error in the latter case);
     *         `true` otherwise.
     */
    bool push_request(qb::http::Request request, ResponseCallback callback);
    /**
     * @brief Coroutine single request.
     * @param request The request to send.
     * @return An awaiter resolving to the response (or a synthesized error response).
     */
    [[nodiscard]] qb::http::async::awaiter<qb::http::Response> push_request(qb::http::Request request);
    /**
     * @brief Queue multiple requests, delivering all responses once via a single callback.
     * @param requests The requests to send; an empty vector invokes @p callback with `{}`.
     * @param callback Invoked once with responses in request order.
     * @return `false` if @p callback is empty or any request failed to queue; `true` otherwise.
     */
    bool push_requests(std::vector<qb::http::Request> requests, BatchResponseCallback callback);
    /**
     * @brief Coroutine batch request.
     * @param requests The requests to send.
     * @return An awaiter resolving to all responses in request order.
     */
    [[nodiscard]] qb::http::async::awaiter<std::vector<qb::http::Response>> push_requests(std::vector<qb::http::Request> requests);

    /** @brief Set the timeout applied to connection attempts. */
    void
    set_connect_timeout(qb::duration value) noexcept {
        _connect_timeout = value;
    }
    /** @brief Set the per-request timeout (also bounds time spent pending in the queue). */
    void
    set_request_timeout(qb::duration value) noexcept {
        _request_timeout = value;
    }
    /** @brief Enable/disable automatic reconnection while requests are pending (default: enabled). */
    void
    set_auto_reconnect(bool value) noexcept {
        _auto_reconnect = value;
    }
    /** @brief Set the maximum number of simultaneously queued (pending + active) requests. */
    void
    set_max_pending_requests(std::size_t value) noexcept {
        _max_pending_requests = value;
    }
    /**
     * @brief Enable/disable TLS server certificate verification for https targets.
     * @param value `true` (default) verifies the chain + hostname; `false` disables
     *              verification (only for trusted/self-signed endpoints).
     * @note Must be set before connect(); applied when the secure connection is opened.
     */
    void
    set_verify_peer(bool value) noexcept {
        _verify_peer = value;
    }
    /** @return `true` if TLS server certificate verification is enabled. */
    [[nodiscard]] bool
    verify_peer() const noexcept {
        return _verify_peer;
    }

    /** @return Tuple of {total, successful, failed} request counts since construction. */
    [[nodiscard]] std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>
    get_stats() const noexcept {
        return {_total_requests, _successful_requests, _failed_requests};
    }

    /** @return Number of requests currently in flight (0 or 1). */
    [[nodiscard]] std::size_t
    get_active_request_count() const noexcept {
        return _active_request ? 1u : 0u;
    }

    /** @return The origin URI this client is bound to. */
    [[nodiscard]] qb::io::uri const &
    get_base_uri() const noexcept {
        return _base_uri;
    }

private:
    void                                            initialize_from_uri(qb::io::uri const &uri);
    void                                            create_connection();
    void                                            ensure_absolute_uri(qb::http::Request &request);
    [[nodiscard]] std::optional<qb::http::Response> prepare_request(qb::http::Request &request);
    void                                            hold_through_current_tick();
    void                                            enter_user_callback();
    void                                            leave_user_callback() noexcept;
    // Invoke a user-supplied callback under a callback_scope, containing any
    // exception it throws. User callbacks are reached from qb-io's noexcept
    // dispatch (protocol onMessage / timeout / disconnect events), where an
    // escaping exception would call std::terminate; this is the single
    // chokepoint that prevents it.
    template <typename Fn>
    void invoke_user_callback(Fn &&fn) noexcept;
    void reset_deferred_connection_if_ready();
    void process_pending_requests();
    void arm_pending_timeout(std::uint64_t request_id);
    bool fail_pending_request(std::uint64_t request_id, std::string const &error, qb::http::status status = qb::http::status::REQUEST_TIMEOUT);
    void handle_connection_success();
    void handle_connection_failure(std::string const &error);
    void handle_response(qb::http::Response response);
    void handle_timeout();
    void handle_disconnected(int reason);
    void fail_active_request(std::string const &error, qb::http::status status = qb::http::status::BAD_GATEWAY);
    void fail_all_requests(std::string const &error, qb::http::status status = qb::http::status::SERVICE_UNAVAILABLE);
    [[nodiscard]] bool               has_pending_work() const noexcept;
    [[nodiscard]] qb::http::Response create_error_response(qb::http::status status, std::string const &message);
};

/** @brief Lowercase alias for `Client`. */
using client = Client;

/**
 * @brief Create a shared HTTP/1.1 client bound to @p base_uri.
 * @param base_uri Origin URI string (see `Client::Client(std::string const&)`).
 * @return A `std::shared_ptr<Client>`.
 * @throws std::invalid_argument on an unsupported scheme or missing host.
 */
std::shared_ptr<Client> make_client(std::string const &base_uri);
/**
 * @brief Create a shared HTTP/1.1 client bound to @p uri.
 * @param uri Origin URI (see `Client::Client(qb::io::uri const&)`).
 * @return A `std::shared_ptr<Client>`.
 * @throws std::invalid_argument on an unsupported scheme or missing host.
 */
std::shared_ptr<Client> make_client(qb::io::uri const &uri);

} // namespace qb::http1

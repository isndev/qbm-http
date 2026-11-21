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
#include <cstdint>
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
#include "../retry_policy.h"
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
 * @brief The automatic reconnection's backoff (Huly QB-103): `qb::http::RetryPolicy`, the same
 *        shape as `qb::redis::RetryPolicy` -- see `enable_auto_reconnect()` for the run it drives.
 */
using RetryPolicy = qb::http::RetryPolicy;

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
    /// The batch this request is a member of, and its place there; 0 for a request with a callback of its own. A member
    /// has no callback: its answer is recorded in its batch, whose callback is what the program hears.
    std::uint64_t batch_id    = 0;
    std::size_t   batch_index = 0;
    /// Its number among the requests pushed alone on this client; 0 for a member of a batch. What a push names when an
    /// exception leaves it and it takes its request back.
    std::uint64_t id = 0;
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
    // The connector's epoch (Huly QB-103): `start_connection()` bumps it and the connector's
    // completion carries the value it was started with, so a completion the client has given up
    // on -- its own deadline fired first, or `disconnect()` was called while it was in flight --
    // is dropped (its socket closes with the callback's argument) instead of clobbering the state
    // of whatever came after it. `_transport_started` says the connector's socket was handed to
    // the transport and `start()`ed, i.e. that a `disconnected` event will follow a close;
    // `_transport_closing` says that close was asked and its `disconnected` has not run yet -- so
    // a `disconnected` arriving while a NEWER connector is pending is the old transport's, stale.
    std::uint64_t _connect_epoch     = 0;
    bool          _connector_pending = false;
    bool          _transport_started = false;
    bool          _transport_closing = false;
    // Which connection a close owns (Huly QB-1246): the transports this io has started, counted -- the count is the number
    // of the last one --, and the number of the last one whose `disconnected` has run. A close writes down the number of
    // the transport it ends before it calls the callbacks of what it ends, and ends that transport after them only if it
    // has not ended meanwhile: a callback that runs the loop can see it end and the next connection come up, which is not
    // this close's to end.
    std::uint64_t _transports_started = 0;
    std::uint64_t _transport_ended    = 0;
    // A connect() asked while a transport is closing starts only once that transport's
    // `disconnected` has run: libev invokes pending events LIFO, so a connector started now could
    // complete -- and `start()` the new transport -- BEFORE the old transport's deferred dispose,
    // which would then find `_reason` reset, dispose the NEW transport as "Connection lost" and stop
    // its watcher. The HTTP/1.1 client defers its reconnects for the same reason.
    bool _connect_after_close = false;

    // Protocol handlers
    H2Protocol *_h2_protocol = nullptr;

    // Request management
    std::deque<std::unique_ptr<RequestContext>>                       _pending_requests;
    qb::unordered_map<uint32_t, std::unique_ptr<RequestContext>>      _active_requests;
    qb::unordered_map<uint64_t, std::unique_ptr<BatchRequestContext>> _active_batches;
    uint64_t                                                          _next_batch_id   = 1;
    uint64_t                                                          _next_request_id = 1; ///< RequestContext::id

    // Configuration
    qb::duration _connect_timeout        = std::chrono::seconds(30);
    qb::duration _request_timeout        = std::chrono::seconds(60);
    bool         _verify_peer            = true; /**< Verify the server TLS certificate (h2 is TLS-only). */
    size_t       _max_concurrent_streams = 100;
    size_t       _max_pending_requests =
        1024; /**< Bound on outstanding (pending + active) requests; rejects with 503 past this (DoS guard, matches http1/http3). */
    bool _auto_reconnect = true;
    // The reconnection run (Huly QB-103): the policy, the attempts made since the last connection
    // that came up, and the one scheduled attempt, timed by the same one-shot timeout the connect
    // and request deadlines use (`arm_request_timeout` folds it in). `_reconnect_firing` marks a
    // `connect()` made BY the run, which keeps its count; `_in_failure_pass` marks a failure
    // handler failing the outstanding work, during which a request pushed from a callback queues
    // and the handler decides once, through the policy, instead of the push connecting on its own.
    RetryPolicy _reconnect_policy{};
    int         _reconnect_attempts     = 0;
    bool        _reconnect_scheduled    = false;
    bool        _reconnect_firing       = false;
    bool        _in_failure_pass        = false;
    bool        _intentional_disconnect = false; ///< disconnect() was asked: the disconnected that follows starts no run (as http1)
    bool        _destroying             = false; ///< The destructor runs: nothing is accepted, armed or connected (Huly QB-1246)
    // An explicit disconnect() of a live connection delivers GOAWAY(NO_ERROR) before the socket closes (Huly QB-1059):
    // `_graceful_close_pending` while that delivery runs, bounded by GOAWAY_FLUSH_LIMIT; the epoch ties the limit's timer to its close.
    bool                                  _graceful_close_pending = false;
    std::uint64_t                         _graceful_close_epoch   = 0;
    std::chrono::steady_clock::time_point _reconnect_started_at{};
    qb::duration                          _reconnect_delay{};

    // linger() as it was before this client ended a connection for a flood (its own GOAWAY(ENHANCE_YOUR_CALM)): that
    // one connection is closed at once -- a linger of zero -- and the setting, which is the client's for every
    // connection it makes, is put back when the close is done, in on(event::dispose) (Huly QB-1270).
    std::optional<qb::duration> _linger_before_flood;

    // Callbacks
    std::vector<ConnectionCallback> _connection_callbacks;

    // The answers this client owes, in the order it came to owe them (Huly QB-1246). An answer the client gives by itself
    // -- a refusal, a connect() on a connected client, an empty batch, a coroutine push completed at once -- is given
    // inside the call only when no callback of this client is on the stack and nothing is owed; an answer the loop brings
    // -- a response, a timeout, a failure, a close -- is given at once when nothing is owed. Otherwise it is kept here.
    // What is kept is heard in two places only: the client's turn (a task in the loop's deferred queue, one a loop turn
    // at most), and its destructor. So the order is total, and what a callback pushes is never answered inside that push.
    std::deque<std::function<void()>> _owed;
    std::uint64_t                     _owed_heard      = 0;     ///< How many of them were heard: a turn hears those owed as it starts
    bool                              _turn_asked      = false; ///< The client's turn is in the loop's queue
    int                               _callback_depth  = 0;     ///< Callbacks of this client on the stack
    int                               _destroy_answers = 0;     ///< Pushes the destructor's callbacks made, being answered inside themselves
    struct CallbackScope;                                       ///< Counts one callback while it runs
    enum class from : bool { the_client, the_loop };            ///< Who gives an answer: the client by itself, or the loop that brings it

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

    /// Every request in flight or queued hears once (503, "Client destroyed"), every connect() still waiting hears `false` once. From
    /// one of those callbacks a request pushed, alone or in a batch, is answered inside the push (503), and a connect() is refused: it
    /// returns false and its callback is never called. A callback that throws is logged. Nothing is armed: safe in static storage.
    ~Client();
    Client(const Client &)            = delete; // non-copyable and non-movable: the base class supports neither
    Client &operator=(const Client &) = delete;
    Client(Client &&)                 = delete;
    Client &operator=(Client &&)      = delete;

    /**
     * @brief Connect to the server (callback-style).
     * @param callback Callback invoked on success or failure. Pass `nullptr`
     *                 for fire-and-forget (you will still be able to
     *                 `push_request` before connection completes; they will
     *                 be queued and flushed on handshake).
     * @return true when the callback will hear the outcome -- at once when already connected, no callback of this client
     *         on the stack and no answer owed, on the client's turn of the loop otherwise; with the attempt under way or
     *         the one this call starts when not connected. false only while the client is being destroyed: nothing
     *         starts, and the callback is never called.
     *
     * @note Asked from a callback of a close, of a failure or of a lost connection, the attempt starts once the
     *       transport that ended is torn down, never under that callback; its connect timeout counts from the ask.
     *       Where that teardown waits for the callback's return, a loop run there to wait hears false at that deadline
     *       and nothing starts afterwards: return instead (the coroutine connect() answers false there, on its turn).
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
     * failed) -- `false`, "HTTP/2 connection is closing", on the client's turn
     * when awaited from a callback the client runs for a close or a failure. Usage:
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

    /// How long an explicit disconnect() waits for its GOAWAY to be delivered -- behind whatever the
    /// connection still had to send -- before it ends the connection anyway: a peer that stopped
    /// reading cannot hold the close longer (Huly QB-1059).
    static constexpr qb::duration GOAWAY_FLUSH_LIMIT = std::chrono::seconds(1);

    /**
     * @brief Disconnect from server
     * @details The outstanding requests fail at once (`503`, "Connection closed"). A live connection
     *          is announced to the server first, as RFC 9113 §6.8 asks: GOAWAY(NO_ERROR) leaves after
     *          what the connection still had to send, then qb-io ends the transport -- its loop shuts
     *          the sending side down and closes the descriptor after the server (Huly QB-1060,
     *          QB-1270) -- at the latest after GOAWAY_FLUSH_LIMIT, when the server no longer reads.
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
     * @param callback Response handler; must be non-null. A request the client refuses at once -- another origin, the
     *                 pending bound, a request the connection cannot take -- is answered inside this call when no
     *                 callback of this client is on the stack and no answer is owed; otherwise on the client's turn of
     *                 the loop, in the order the client came to owe its answers. A callback that pushes back at every
     *                 refusal is never called from inside its own push. Bound such a retry all the same, with a delay:
     *                 it spins otherwise.
     *                 With callbacks that run no loop turn of their own, no callback of a client is called inside
     *                 another one of the same client: nesting is exactly one outside the destructor -- and what a
     *                 disconnect() called from a callback ends is heard on the client's turn too.
     *                 A callback that runs the loop -- qb::io::async::run(), run_once(), run_until(), run_sync() --
     *                 receives inside that loop whatever the client owes, its own refusals included: one that pushes
     *                 a refused request back and then runs the loop recurses once per refusal. To relaunch without
     *                 nesting, push back and return.
     * @return @c false if @p callback is null; if the request would take the queued + active count past
     *         set_max_pending_requests() -- @p callback then hears a 503, inside the call or on that turn; or if the
     *         push is made from inside the answer of a push the destructor refused, where @p callback is never called.
     *         @c true otherwise, a request for another origin (400) included.
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
     * @param callback Callback to handle all responses (in same order as requests): one answer, given as a request's
     *                 is -- inside this call for an empty batch or one whose members are all refused, when no callback of
     *                 this client is on the stack and no answer is owed; on the client's turn of the loop otherwise.
     * @return @c false if @p callback is null (for a batch that is not empty), if a member was refused by the pending
     *         bound, or if the push is made from inside the answer of a push the destructor refused, where @p callback
     *         is never called. @c true otherwise.
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
     * @param timeout Connect timeout (a `qb::duration`)
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
     * @param timeout Per-request timeout (a `qb::duration`)
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
     * @brief Arm the automatic reconnection with its backoff (Huly QB-103); the same call as
     *        `qb::redis::connector::enable_auto_reconnect`.
     *
     * A RUN is the sequence of attempts between a connection loss and the next connection that
     * comes up, and it exists only while requests wait: the loss fails the outstanding work with a
     * 503, and what the failure callbacks push back is what the run reconnects for (a request
     * pushed while the client is down starts one the same way). Attempt 1 is immediate, attempt 2
     * waits `initial_delay`, every further one multiplies the wait by `multiplier` up to
     * `max_delay`, jittered; `max_attempts` bounds the run. Once exhausted, the waiting requests
     * fail with a 503 whose body says so and the client stays disconnected until the next
     * `connect()` -- explicit, or the auto-connect of a request pushed afterwards -- which starts a
     * fresh run. A connection that comes up ends the run and resets its count; so do an explicit
     * `connect()` and an explicit `disconnect()` -- which also starts none: the user asked out, so
     * the outstanding work fails with "Connection closed" and, as in the HTTP/1.1 client, only a
     * request pushed afterwards (from that verdict's callback included) connects again, on its own.
     * `on_retry(attempt, next_delay)` is called before each wait with the number of attempts
     * failed so far. The connect timeout of every attempt is `set_connect_timeout()`'s -- the one
     * redis field this policy does not carry.
     *
     * Every attempt fires from the client's own timer, after the transport that dropped has been
     * disposed, never from inside the handler that observed the failure; a request pushed from a
     * failure callback (the retry pattern) queues behind the attempt the run decides on instead
     * of connecting on its own. Until 3.2 both were otherwise: the reconnection was immediate,
     * unbounded, and started from inside the failing handler.
     */
    void
    enable_auto_reconnect(RetryPolicy policy = RetryPolicy{}) noexcept {
        _auto_reconnect   = true;
        _reconnect_policy = std::move(policy);
    }
    /**
     * @brief Disarm the automatic reconnection; an attempt already scheduled still fires (the
     *        same rule as redis: in-flight reconnects finish). Keeps the policy.
     */
    void
    disable_auto_reconnect() noexcept {
        _auto_reconnect = false;
    }
    /** @brief True while a reconnection run has an attempt scheduled or in flight. */
    [[nodiscard]] bool
    is_reconnecting() const noexcept {
        return _reconnect_scheduled || (_is_connecting && _reconnect_attempts > 0);
    }
    /**
     * @brief Attempts made in the current reconnection run: since the last connection that came
     *        up, or the last explicit `connect()` / `disconnect()`. An attempt counts when it is
     *        scheduled, so this reads 1 while the immediate first attempt is in flight.
     */
    [[nodiscard]] int
    reconnect_attempts() const noexcept {
        return _reconnect_attempts;
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

    /// Set the largest response body this client accepts, in bytes; 0 = none (Huly QB-1248). 100 MiB by default: a response past it
    /// has its stream reset and its request fails, 502, the error naming the limit; the connection and its other streams go on.
    void
    set_max_body_size(std::size_t value) noexcept {
        _max_body_size = value;
    }
    /// The largest response body this client accepts, in bytes; 0 = none.
    [[nodiscard]] std::size_t
    max_body_size() const noexcept {
        return _max_body_size;
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
    std::size_t _max_body_size = qb::http::protocol_limits::MAX_BODY_SIZE; ///< set_max_body_size(); 0: none (QB-1248)
    /// Initialize the client from @p uri
    void initialize_from_uri(const qb::io::uri &uri);

    /// Start connection attempt
    void start_connection();

    /// Normalize relative request URI against the client's HTTPS base URI.
    void ensure_absolute_uri(qb::http::Request &request);

    /// Normalize and validate a request before it can be queued.
    [[nodiscard]] std::optional<qb::http::Response> prepare_request(qb::http::Request &request);

    /// Process pending requests queue
    void process_pending_requests(from who = from::the_loop);

    /// Handle successful connection
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
    /// The outstanding work, out of the client: what a failure answers once the registries no longer hold it.
    struct DetachedRequests {
        qb::unordered_map<uint32_t, std::unique_ptr<RequestContext>>      active;
        std::deque<std::unique_ptr<RequestContext>>                       pending;
        qb::unordered_map<uint64_t, std::unique_ptr<BatchRequestContext>> batches;
    };
    /// Takes every request and every batch the client holds: from here on a push is new work, which the failure of what
    /// was taken does not answer.
    [[nodiscard]] DetachedRequests detach_requests();
    /// Answers what detach_requests() took, each with @p error_message. fail_all_requests() is the two, one after the other.
    /// Every one of them is answered whatever a callback throws; the first exception goes on once the last has heard.
    void fail_detached(DetachedRequests detached, const std::string &error_message, from who = from::the_loop);
    /// Takes back, unanswered, what a call of the program pushed and an exception is leaving that call with: the request
    /// @p request_id, or every member of the batch @p batch_id and the batch with its callback. Never throws.
    void withdraw(std::uint64_t request_id, std::uint64_t batch_id) noexcept;
    /// Whether an answer @p who gives is given now, or kept for the client's turn (the rule above `_owed`).
    [[nodiscard]] bool given_now(from who) const noexcept;
    /// Calls @p fn, a callback of the program, now: counted while it runs. What @p fn throws goes on to the caller.
    template <typename Fn>
    void call_now(Fn &&fn);
    /// Keeps @p answer for the client's turn, which is asked.
    void owe(std::function<void()> answer) noexcept;
    /// An answer the client gives by itself: now, or kept.
    void answer_by_itself(std::function<void()> answer);
    /// The outcome of a connect(), told to @p callback: now, or kept.
    void tell_connect(ConnectionCallback const &callback, bool ok, std::string const &error, from who);
    /// The answer of a batch, told to its callback: now, or kept.
    void tell_batch(BatchResponseCallback callback, std::vector<qb::http::Response> responses, from who);
    /// The answer of one request -- its response, a failure, a refusal --: a member of a batch is recorded in its batch at
    /// once (the batch's callback is the answer); a request's own callback is called now, or kept behind what is owed.
    /// Every answer of a request goes through here.
    void give(RequestContext &ctx, qb::http::Response response, from who = from::the_loop);
    /// One member of a batch has its answer: recorded; the batch's callback is told when it was the last.
    void batch_member_answered(std::uint64_t batch_id, std::size_t index, qb::http::Response response, from who);
    /// Asks the client's turn of the loop, if it is not asked.
    void ask_turn() noexcept;
    /// The client's turn: what was owed as it starts is heard, in order.
    void run_turn() noexcept;
    /// A close or a failure runs the callbacks of what it ends: the coroutine connect() answers there at once -- one rule, as
    /// what it would wait for is, after most of them, heard only once those callbacks return (Huly QB-1246).
    int _closing_callbacks = 0;

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
     * @brief Schedule the next attempt of the reconnection run through the policy, or fail the
     *        outstanding work when the run is exhausted. Never connects synchronously: the attempt
     *        fires from `on(timeout)`, after the transport that dropped has been disposed.
     */
    void attempt_reconnection();
    /// The scheduled attempt is due: connect, unless something connected meanwhile or nothing waits.
    void               fire_scheduled_reconnection();
    [[nodiscard]] bool reconnect_due(std::chrono::steady_clock::time_point now) const noexcept;
    /**
     * @brief Tear the connection down with `error_message` as the verdict of the connect callbacks
     *        and of every outstanding request, keeping what the failure callbacks re-queue for the
     *        reconnection decision the transport's `disconnected` event makes. The body of
     *        `disconnect()`, without the run reset an explicit disconnect implies.
     */
    void close_connection(const std::string &error_message, from who = from::the_loop);
    /**
     * @brief Fail the outstanding work as a failure pass: a request pushed from one of its
     *        callbacks queues (auto-reconnect on) instead of connecting on its own.
     */
    void run_failure_pass(const std::string &error_message);

    /**
     * @brief Create error response
     * @param status HTTP status code
     * @param message Error message
     * @return Error response object
     */
    qb::http::Response create_error_response(qb::http::status status, const std::string &message);
};
using client = Client;

/// The protocol counts the PONGs and SETTINGS ACKs still queued in the client's output on what its socket took,
/// `bytes_written()`: without it they would be forgiven only once the output is empty (Huly QB-1270).
static_assert(qb::protocol::http2::counts_bytes_written<Client>, "the HTTP/2 client counts the bytes its socket took");

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

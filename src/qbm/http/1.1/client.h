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

class Client;

/**
 * @brief The timer of one queued request's wait, owned by the request (Huly QB-1246): it goes when the request is sent
 *        or answered, whatever answers it, so an answered request leaves no timer armed behind it. A request has one
 *        at most.
 */
class pending_timer : public qb::io::async::with_timeout<pending_timer> {
    Client       &_client;
    std::uint64_t _request_id;

public:
    /// @param after The request timeout: how long the request may wait in the queue.
    pending_timer(Client &client, std::uint64_t request_id, qb::duration after)
        : qb::io::async::with_timeout<pending_timer>(after)
        , _client(client)
        , _request_id(request_id) {}

    /// The wait has lasted the request timeout: the request fails, `408`, if it is still queued.
    void on(qb::io::async::event::timer const &) noexcept;
};

/**
 * @brief Internal bookkeeping for a single in-flight or pending request.
 */
struct RequestContext {
    std::uint64_t                         request_id = 0; /**< Monotonic id used to match pending timeouts: never used twice. */
    qb::http::Request                     request;        /**< The prepared request to send. */
    ResponseCallback                      callback;       /**< User callback to invoke with the response. */
    std::chrono::steady_clock::time_point created_at;     /**< Enqueue time stamp. */
    std::optional<pending_timer>          timer;          /**< Armed while the request waits in the queue. */
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
    class tick_hold;
    struct failure_cohort;
    friend class pending_timer;

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

    qb::io::uri _base_uri;
    std::string _host;
    bool        _is_connected           = false;
    bool        _is_connecting          = false;
    bool        _destroying             = false; ///< The destructor runs: nothing is accepted, armed or connected (Huly QB-1246)
    bool        _intentional_disconnect = false;
    // No `std::shared_ptr<Client> _callback_self_guard` member: the self-hold that keeps this
    // client alive through the current loop turn is owned by the deferred closure that releases
    // it (see `hold_through_current_tick`). Parking it in a member made it a self-referential
    // cycle whenever that closure never got to run.
    std::size_t _callback_depth = 0;
    std::size_t _holds_queued   = 0; ///< Holds the loop's deferred queue owns (tick_hold): none left means none keeps this client (QB-1246)
    // The answers this client owes, in the order it came to owe them (Huly QB-1246). An answer the client gives by itself
    // -- a refusal, a connect() on a connected client, an empty batch, a coroutine push completed at once -- is given
    // inside the call only when no callback of this client is on the stack and nothing is owed; an answer the loop brings
    // -- a response, a timeout, a failure, a close -- is given at once when nothing is owed. Otherwise it is kept here.
    // What is kept is heard in two places only: the client's turn (a task of its own in the loop's deferred queue, one a
    // loop turn at most), and its destructor. So the order is total, and what a callback pushes is never answered in the push.
    std::deque<std::function<void()>> _owed;
    std::uint64_t                     _owed_heard      = 0;     ///< How many of them were heard: a turn hears those owed as it starts
    bool                              _turn_asked      = false; ///< The client's turn is in the loop's queue
    std::size_t                       _destroy_answers = 0;     ///< Pushes the destructor's callbacks made, being answered inside themselves
    // While true, _connection still owns the retired dispatch. connect() may
    // record a new intent, but only deferred cleanup can replace that owner.
    bool _deferred_connection_reset = false;

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
    /**
     * @brief Disconnect and fail any outstanding requests.
     * @details Every request in flight or queued hears once, with a 503 ("Connection closed"), and every `connect()`
     *          still waiting hears `false` once. From one of those callbacks a request pushed, alone or in a batch,
     *          is answered inside the push (503) -- and one pushed from inside THAT answer is refused by the return
     *          value alone, `false`, its callback never called --, and a `connect()` is refused: it returns false and
     *          its callback is never called. Nothing is queued, armed or connected. A client with static storage is destroyed after
     *          its thread's event loop (`listener::current`, which `exit()` destroys first): the callbacks then run
     *          there, where nothing can be asked of the loop any more -- no timer, no connection (Huly QB-1246). The
     *          coroutine forms need nothing: the coroutines parked on them were destroyed with the loop.
     */
    ~Client();

    Client(Client const &)            = delete;
    Client &operator=(Client const &) = delete;

    /**
     * @brief Open (or reuse) the connection, notifying via callback.
     * @param callback Invoked with the connection outcome. If already connected, it hears success inside this call,
     *                 or on the client's turn of the loop when a callback of this client is on the stack or an answer
     *                 is owed (as a refusal is heard: push_request()); queued while a connection is in progress. May be empty.
     *                 During retirement, the accepted next attempt starts after
     *                 the old callbacks and protocol/I/O dispatch have unwound.
     * @return `true` when the callback will hear the outcome -- as said above when already connected, with the attempt
     *         under way or the one this call starts otherwise. `false` when the client refuses -- it is being destroyed,
     *         or has no shared owner (`make_client`) -- and nothing starts: the callback is then never called. Also
     *         `false` for an empty callback while an attempt is under way: nothing was queued.
     */
    bool connect(ConnectionCallback callback);
    /**
     * @brief Coroutine connect.
     * @return An awaiter that resolves to a `ConnectResult` describing the outcome. Awaited from a callback the
     *         client runs for a close or a failure: `false`, "HTTP/1.1 connection is closing", on the client's turn.
     */
    [[nodiscard]] qb::http::async::awaiter<ConnectResult> connect();
    /**
     * @brief Intentionally close the connection and fail all active/pending requests.
     *
     * Disables auto-reconnect for the current cycle; the underlying connection is
     * reset before returning, or deferred until the current callback dispatch unwinds.
     * Requests and connects submitted by failure callbacks belong to the next cycle.
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
     * @param callback Invoked with the response or a synthesized error response. A request the client refuses at
     *                 once -- another origin, the pending-request limit, nothing to connect for it (automatic
     *                 reconnection off), a request that cannot be written -- is answered inside this call when no
     *                 callback of this client is on the stack and no answer is owed; otherwise on the client's turn
     *                 of the loop, in the order the client came to owe its answers. A callback that pushes back at
     *                 every failure is never called from inside its own push. Bound such a retry all the same, with
     *                 a delay: it spins otherwise.
     *                 With callbacks that run no loop turn of their own, no callback of a client is called inside
     *                 another one of the same client: nesting is exactly one outside the destructor -- and what a
     *                 disconnect() called from a callback ends is heard on the client's turn too.
     *                 A callback that runs the loop -- qb::io::async::run(), run_once(), run_until(), run_sync() --
     *                 receives inside that loop whatever the client owes, its own refusals included: one that pushes
     *                 a refused request back and then runs the loop recurses once per refusal. To relaunch without
     *                 nesting, push back and return.
     * @return `false` if @p callback is empty; if the pending-request limit is reached (the callback hears a 503,
     *         inside the call or on the client's turn of the loop); or if the push is made from inside the
     *         answer of a push the destructor refused, where the callback is never called. `true` otherwise.
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
     * @param requests The requests to send; an empty vector answers @p callback with `{}`, as a refusal is heard.
     * @param callback Invoked once with responses in request order -- as push_request()'s callback, inside this
     *                 call or on the client's turn of the loop when every member is refused at once.
     * @return `false` if @p callback is empty or any request failed to queue -- and then, pushed from inside the
     *         answer of a push the destructor refused, with @p callback never called; `true` otherwise.
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
    /**
     * @brief Set the largest response body this client accepts, in bytes; 0 = none (Huly QB-1248).
     * @details `qb::http::protocol_limits::MAX_BODY_SIZE` (100 MiB) by default, read as each response begins: one that declares a
     *          `Content-Length` past it fails before a byte of its body is read, a chunked or close-delimited one once the bytes
     *          it delivered pass it, with a 502 whose error names the limit. A response is held in the connection's input buffer
     *          until it completes, so qb-io's read cap (`QB_MAX_READ_BUFFER_SIZE`, 200 MiB) bounds it whatever this is: a response
     *          it cut fails naming that cap instead.
     */
    void
    set_max_body_size(std::size_t value) noexcept {
        _max_body_size = value;
    }
    /** @return The largest response body this client accepts, in bytes; 0 = none. */
    [[nodiscard]] std::size_t
    max_body_size() const noexcept {
        return _max_body_size;
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
    enum class from : bool { the_client, the_loop }; ///< Who gives an answer: the client by itself, or the loop that brings it
    /// Whether an answer @p who gives is given now, or kept for the client's turn (the rule above `_owed`).
    [[nodiscard]] bool given_now(from who) const noexcept;
    void               owe(std::function<void()> answer) noexcept;     ///< Kept for the client's turn, which is asked
    void               answer_by_itself(std::function<void()> answer); ///< An answer the client gives by itself: now, or kept
    void               tell_connect(ConnectionCallback const &callback, bool ok, std::string const &error, from who) noexcept;
    void               ask_turn() noexcept;       ///< The client's turn is asked of the loop, if it is not
    void               run_turn() noexcept;       ///< The client's turn: what was owed as it starts is heard
    [[nodiscard]] bool can_send() const noexcept; ///< Connected, on a connection that is open
    void               enter_user_callback();
    void               leave_user_callback() noexcept;
    // Call a user-supplied callback now, under a callback_scope, containing any
    // exception it throws. User callbacks are reached from qb-io's noexcept
    // dispatch (protocol onMessage / timeout / disconnect events), where an
    // escaping exception would call std::terminate; this is the single
    // chokepoint that prevents it. Whether an answer is called now or kept is
    // decided before it (given_now()).
    template <typename Fn>
    void           call_now(Fn &&fn) noexcept;
    void           reset_deferred_connection_if_ready();
    void           retire_connection(bool defer_cleanup = true);
    failure_cohort detach_failure_cohort(bool fail_pending);
    void           fail_retired_requests(failure_cohort &cohort, std::string const &error, qb::http::status active_status,
                                         std::string const &pending_error, qb::http::status pending_status, from who = from::the_loop);
    void           process_pending_requests();
    void           arm_pending_timeout(std::uint64_t request_id);        ///< For a request still queued; nothing otherwise
    void           pending_timed_out(std::uint64_t request_id) noexcept; ///< The timer of a queued request's wait fired
    /// The answer of one request -- its response, a failure --: its timer is stopped first, then its callback is called,
    /// or kept for the client's turn behind what is owed. Every answer of a request goes through here. @p make builds
    /// the response, under the callback's containment.
    template <typename Make>
    void give(RequestContext &ctx, Make &&make, from who = from::the_loop) noexcept;
    bool fail_pending_request(std::uint64_t request_id, std::string const &error, qb::http::status status = qb::http::status::REQUEST_TIMEOUT);
    void handle_connection_success();
    void handle_connection_failure(std::string const &error);
    void handle_response(qb::http::Response response);
    void handle_switched_protocols(qb::http::Response response); // a 101: the connection retired, one not offered failed
    void handle_timeout();
    void handle_disconnected(int reason, std::string const &cut = {});
    void fail_active_request(std::string const &error, qb::http::status status = qb::http::status::BAD_GATEWAY);
    void fail_all_requests(std::string const &error, qb::http::status status = qb::http::status::SERVICE_UNAVAILABLE);
    [[nodiscard]] bool               has_pending_work() const noexcept;
    [[nodiscard]] qb::http::Response create_error_response(qb::http::status status, std::string const &message);

    std::size_t _max_body_size = qb::http::protocol_limits::MAX_BODY_SIZE; ///< set_max_body_size(); 0: none (QB-1248)
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

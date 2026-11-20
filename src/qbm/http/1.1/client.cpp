/**
 * @file qbm/http/1.1/client.cpp
 * @brief Implementation of the persistent HTTP/1.1 client.
 *
 * Contains the out-of-line definitions for `qb::http1::Client` (connection lifecycle, request queueing/dispatch, timeout and
 * reconnection handling, batch coordination, and the coroutine awaiter factories) together with the private
 * `connection<Transport>` adapter that bridges the client to qb-io's asynchronous TCP/TLS transports.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./client.h"

#include <chrono>
#include <stdexcept>
#include <utility>

#include <qb/io/async/tcp/connector.h>
#include <qb/io/transport/tcp.h>
#ifdef QB_HAS_SSL
#include <qb/io/transport/stcp.h>
#endif

#include "../detail/client_callback.h"
#include "../headers.h"
#include "../origin.h"
#include "../utility.h"
#include "./http.h"

namespace qb::http1 {
namespace {

[[nodiscard]] bool
has_connection_close(qb::http::Response const &response) {
    auto it = response.headers().find("Connection");
    if (it == response.headers().end()) {
        return false;
    }
    for (auto const &value : it->second) {
        for (auto token : qb::http::utility::split_string<std::string>(value, ",")) {
            token = std::string(qb::http::utility::trim_http_whitespace(token));
            if (qb::http::utility::iequals(token, "close")) {
                return true;
            }
        }
    }
    return false;
}

} // namespace

template <typename Transport>
class Client::connection final
    : public connection_base
    , public qb::io::async::tcp::client<connection<Transport>, Transport>
    , public qb::io::use<connection<Transport>>::timeout {
    using base_t = qb::io::async::tcp::client<connection<Transport>, Transport>;
    Client               &_owner;
    qb::http::method      _active_method = qb::http::method::GET;
    std::shared_ptr<bool> _alive         = std::make_shared<bool>(true);

public:
    using http_protocol = qb::protocol::http::client<connection<Transport>>;

    /// Typed protocol handle, captured from switch_protocol so on(disconnected) can flush a close-delimited response body (no
    /// Content-Length / Transfer-Encoding) that the parser buffered until EOF. Owned by the io base's protocol list; not freed here.
    http_protocol *_http_protocol = nullptr;

    explicit connection(Client &owner)
        : _owner(owner) {
        _http_protocol = this->template switch_protocol<http_protocol>(*this);
        this->setTimeout(qb::duration::zero());
        this->set_max_message_size(std::numeric_limits<std::size_t>::max()); // the parser bounds a response, by its body limit
    }

    ~connection() override {
        *_alive = false;
    }

    [[nodiscard]] bool
    http1_response_body_forbidden() const noexcept {
        return _active_method == qb::http::Method::HEAD;
    }
    /// Protocol hook: the limits of the next response -- the defaults, the body's this client's (defined below; Huly QB-1248).
    [[nodiscard]] qb::http::request_limits http_request_limits() const noexcept;

    void
    connect(qb::io::uri const &uri, qb::duration timeout, bool verify_peer) override {
        auto alive = std::weak_ptr<bool>(_alive);
        qb::io::async::tcp::connect<typename Transport::transport_io_type>(
            uri,
            [this, alive, timeout](auto &&socket) {
                auto guard = alive.lock();
                if (!guard || !*guard) {
                    return;
                }
                auto owner_guard = _owner.weak_from_this().lock();
                if (!socket.is_open()) {
                    _owner.handle_connection_failure("Connection failed");
                    return;
                }
                this->transport() = std::forward<decltype(socket)>(socket);
                this->start();
                this->setTimeout(timeout);
                _owner.handle_connection_success();
            },
            timeout, verify_peer);
    }

    void
    disconnect() override {
        // Retiring an attempt invalidates its asynchronous connect completion,
        // even while the old connection must remain alive until dispatch returns.
        *_alive = false;
        this->setTimeout(qb::duration::zero());
        this->base_t::disconnect(1);
    }

    void
    send(qb::http::Request request, qb::duration timeout) override {
        _active_method = request.method();
#ifdef QB_HAS_COMPRESSION
        try {
            if (request.has_header("Content-Encoding")) {
                request.body().compress(request.header("Content-Encoding"));
            }
        } catch (std::exception const &e) {
            _owner.fail_active_request(e.what(), qb::http::status::BAD_REQUEST);
            return;
        }
#else
        request.remove_header("Content-Encoding");
#endif
        try {
            *this << request;
            this->setTimeout(timeout);
        } catch (std::exception const &e) {
            _owner.fail_active_request(e.what(), qb::http::status::BAD_REQUEST);
        }
    }

    [[nodiscard]] bool
    is_open() const noexcept override {
        return this->transport().is_open();
    }

    void
    on(typename http_protocol::response response) {
        const auto status = response.status().code();
        if (status >= 100 && status < 200 && status != 101) [[unlikely]] {
            // RFC 9110 section 15.2: the active request, its deadline and queue await the final response. An interim response of a
            // version other than 1.1 that names a Transfer-Encoding has faulty framing (RFC 9112 §6.1): remembered for the final one.
            _faulty_interim =
                _faulty_interim || (response.has_header("Transfer-Encoding") && !(response.major_version > 0 && response.minor_version > 0));
            return;
        }
        if (status == 101) [[unlikely]]
            return _owner.handle_switched_protocols(std::move(response)); // HTTP/1.1 ends at a 101 on its connection (QB-1248)
        response.keep_alive = response.keep_alive && !std::exchange(_faulty_interim, false); // such a connection is retired after it
        auto owner_guard    = _owner.weak_from_this().lock();
        this->setTimeout(qb::duration::zero());
#ifdef QB_HAS_COMPRESSION
        try {
            if (response.has_header("Content-Encoding")) {
                response.body().uncompress(response.header("Content-Encoding"));
            }
        } catch (std::exception const &e) {
            response.status() = qb::http::status::BAD_REQUEST;
            response.body()   = std::string(e.what());
        }
#endif
        _owner.handle_response(std::move(response));
    }

    void
    on(qb::io::async::event::timeout const &) {
        auto owner_guard = _owner.weak_from_this().lock();
        _owner.handle_timeout();
    }

    void
    on(qb::io::async::event::disconnected const &event) {
        auto owner_guard = _owner.weak_from_this().lock();
        if (_owner._deferred_connection_reset) {
            return;
        }
        // A close-delimited response (no Content-Length, no Transfer-Encoding) is framed by the connection close: deliver its
        // buffered body NOW, before the disconnect tears the active request down. flush_eof dispatches through on(response) ->
        // handle_response, completing the request, so handle_disconnected below then finds nothing to fail. No-op otherwise.
        // Only the peer's close (reason 0) ends such a body: a disconnect for another reason -- a cap qb-io enforced (-3, -2), a
        // protocol error (-1) -- cut it, and the request fails below, as the one-shot client's does (Huly QB-1066).
        if (_http_protocol && event.reason == 0) {
            _http_protocol->flush_eof();
        }
        const auto cut = _http_protocol ? _http_protocol->cut_by(event.reason) : std::string{};
        if (!cut.empty()) {
            // The server is still sending what this client refused: the peer to reset. Closed at once -- a linger of zero,
            // read by the dispose() this handler runs under -- not handed to the loop to be read for linger() (Huly QB-1270).
            this->set_linger(qb::duration::zero());
        }
        _owner.handle_disconnected(event.reason, cut); // a cut names its bound, the body limit or the read cap, once retired (QB-1248)
    }

    void
    on(qb::io::async::event::dispose const &) {}

    bool _faulty_interim = false; ///< An interim response had faulty framing: the final response's connection is not kept (QB-1248)
};

class Client::callback_scope {
    Client &_client;

public:
    explicit callback_scope(Client &client)
        : _client(client) {
        _client.enter_user_callback();
    }

    ~callback_scope() {
        _client.leave_user_callback();
    }
};

/// The share that keeps a client alive to the end of the loop turn, as the closure the deferred queue owns (Huly
/// QB-1246). It is counted while it is queued -- from its construction until it runs, or is destroyed unrun when the
/// queue is dropped --, so the client knows whether one still stands between it and its destruction: a loop turn run
/// from a callback drains it while that callback is on the stack (leave_user_callback()). Copies count each for
/// itself, a moved-from one for nothing: std::function may make either.
class Client::tick_hold {
    std::shared_ptr<Client> _self;

public:
    explicit tick_hold(std::shared_ptr<Client> self) noexcept
        : _self(std::move(self)) {
        ++_self->_holds_queued;
    }
    tick_hold(tick_hold const &other) noexcept
        : _self(other._self) {
        if (_self) {
            ++_self->_holds_queued;
        }
    }
    tick_hold(tick_hold &&other) noexcept
        : _self(std::move(other._self)) {}
    tick_hold &operator=(tick_hold const &) = delete;
    ~tick_hold() {
        if (_self) {
            --_self->_holds_queued; // dropped unrun; the share goes after it, and the client with it when it was the last
        }
    }

    void
    operator()() {
        auto self = std::move(_self); // run: no longer queued, and released when this returns
        --self->_holds_queued;
        self->reset_deferred_connection_if_ready();
        self->run_late_answers(); // the refusals kept for this turn: no callback of the client is on the stack here, or they wait
    }
};

struct Client::failure_cohort {
    std::unique_ptr<RequestContext>                            active;
    std::optional<std::deque<std::unique_ptr<RequestContext>>> pending;
    std::vector<ConnectionCallback>                            callbacks;
};

template <typename Fn>
void
Client::invoke_user_callback(Fn &&fn) noexcept {
    callback_scope scope(*this);
    qb::http::detail::contained("HTTP/1.1", std::forward<Fn>(fn));
}

Client::Client(std::string const &base_uri)
    : Client(qb::io::uri(base_uri)) {}

Client::Client(qb::io::uri const &uri) {
    initialize_from_uri(uri);
}

Client::~Client() {
    // The destruction contract of the three HTTP clients (Huly QB-1246): every request in flight or queued hears once, every
    // connect() still waiting hears `false` once -- disconnect() below answers both --, and from `_destroying` on nothing is
    // accepted, armed or connected: a request pushed from one of those callbacks is answered inside its push, a connect()
    // refused by its return value alone. A client with static storage is destroyed after its thread's event loop, where a
    // timer asked of the loop stops the process.
    _destroying = true;
    try {
        disconnect();
        run_late_answers(); // a refusal still owed its turn is heard here, once
    } catch (...) {
        // An allocation the close makes for itself failed -- its callbacks are contained --: nothing leaves a destructor.
    }
}

void
Client::initialize_from_uri(qb::io::uri const &uri) {
#ifdef QB_HAS_SSL
    if (!qb::http::origin::scheme_eq(uri.scheme(), "http") && !qb::http::origin::scheme_eq(uri.scheme(), "https")) {
        throw std::invalid_argument("HTTP/1.1 client base URI must use http or https");
    }
#else
    if (!qb::http::origin::scheme_eq(uri.scheme(), "http")) {
        throw std::invalid_argument("HTTP/1.1 client base URI must use http when QB_HAS_SSL is disabled");
    }
#endif
    if (uri.host().empty()) {
        throw std::invalid_argument("HTTP/1.1 client base URI is missing a host");
    }
    _base_uri = uri;
    _host     = qb::http::host_header_value(_base_uri);
    create_connection();
}

void
Client::create_connection() {
#ifdef QB_HAS_SSL
    if (qb::http::origin::scheme_eq(_base_uri.scheme(), "https")) {
        _connection = std::make_unique<connection<qb::io::transport::stcp>>(*this);
    } else {
        _connection = std::make_unique<connection<qb::io::transport::tcp>>(*this);
    }
#else
    _connection = std::make_unique<connection<qb::io::transport::tcp>>(*this);
#endif
}

bool
Client::connect(ConnectionCallback callback) {
    if (_destroying) {
        return false; // refused, by the return value alone: the callback of a connect() that starts nothing is never called (QB-1246)
    }
    if (_is_connected) {
        if (callback) {
            invoke_user_callback([&] { callback(true, ""); }); // contained, as every callback of this client (Huly QB-1246)
        }
        return true;
    }
    if (weak_from_this().expired()) {
        return false; // no shared owner to connect for: refused the same way
    }
    if (_is_connecting) {
        if (callback) {
            _connection_callbacks.emplace_back(std::move(callback));
            return true;
        }
        return false;
    }
    if (callback) {
        _connection_callbacks.emplace_back(std::move(callback));
    }
    _intentional_disconnect = false;
    _is_connecting          = true;
    if (_deferred_connection_reset) {
        // The request is accepted, but the old protocol/dispose dispatch may
        // still be on the stack. Deferred cleanup starts this connection intent.
        return true;
    }
    if (!_connection || !_connection->is_open()) {
        create_connection();
    }
    _connection->connect(_base_uri, _connect_timeout, _verify_peer);
    return true;
}

qb::http::async::awaiter<ConnectResult>
Client::connect() {
    auto weak_self = weak_from_this();
    return qb::http::async::make_awaiter<ConnectResult>([weak_self](std::function<void(ConnectResult &&)> complete) mutable {
        auto self = weak_self.lock();
        if (!self) {
            complete(ConnectResult{false, "HTTP/1.1 client no longer available"});
            return;
        }
        if (self->_deferred_connection_reset && self->_callback_depth > 0) {
            // Awaited from a callback of a close -- the connection retired, its callbacks running --, it answers at once.
            // connect(callback) queues the attempt until those callbacks have unwound: a coroutine blocked on it there --
            // run_sync() pumps the loop until it completes -- waited for ever (Huly QB-1246).
            complete(ConnectResult{false, "HTTP/1.1 connection is closing"});
            return;
        }
        // connect() answers through its callback -- at once when connected, at the attempt's end otherwise -- and returns false,
        // given one, only for a client it refuses, whose callback it never calls: the awaiter then completes here. `complete` is
        // COPIED into the callback so this end still holds one (one std::function allocation on a connection attempt: a cold path).
        if (!self->connect([complete](bool ok, std::string const &err) mutable { complete(ConnectResult{ok, err}); })) {
            complete(ConnectResult{false, "HTTP/1.1 client no longer available"});
        }
    });
}

void
Client::disconnect() {
    auto       self_guard    = weak_from_this().lock();
    const bool defer_cleanup = _callback_depth != 0;
    auto       cohort        = detach_failure_cohort(true);
    _intentional_disconnect  = true;
    retire_connection(defer_cleanup);
    fail_retired_requests(cohort, "Connection closed", qb::http::status::SERVICE_UNAVAILABLE, "Connection closed",
                          qb::http::status::SERVICE_UNAVAILABLE);
    if (!defer_cleanup) {
        reset_deferred_connection_if_ready();
    }
}

void
Client::ensure_absolute_uri(qb::http::Request &request) {
    if (!request.uri().host().empty()) {
        return;
    }
    std::string absolute = std::string(_base_uri.scheme()) + "://" + std::string(_base_uri.host());
    if (!_base_uri.port().empty()) {
        absolute.push_back(':');
        absolute += _base_uri.port();
    }
    absolute += request.uri().path().empty() ? "/" : std::string(request.uri().path());
    if (!request.uri().encoded_queries().empty()) {
        absolute.push_back('?');
        absolute += request.uri().encoded_queries();
    }
    request.uri() = qb::io::uri(std::move(absolute));
}

std::optional<qb::http::Response>
Client::prepare_request(qb::http::Request &request) {
    ensure_absolute_uri(request);
    if (request.uri().host().empty()) {
        return create_error_response(qb::http::status::BAD_REQUEST, "HTTP/1.1 request URI is missing a host");
    }
    if (!qb::http::origin::same(request.uri(), _base_uri)) {
        return create_error_response(qb::http::status::BAD_REQUEST, "HTTP/1.1 persistent client only accepts same-origin requests");
    }
    if (!request.has_header("Host")) {
        request.set_header("Host", _host);
    }
    if (!request.has_header("User-Agent")) {
        request.set_header("User-Agent", std::string(qb::http::default_user_agent));
    }
    if (!request.has_header("Accept-Encoding")) {
        request.set_header("Accept-Encoding", qb::http::accept_encoding());
    }
    return std::nullopt;
}

bool
Client::push_request(qb::http::Request request, ResponseCallback callback) {
    if (!callback) {
        return false;
    }
    ++_total_requests;
    if (_destroying) { // pushed from a callback the destructor runs: answered here, never queued, nothing armed (Huly QB-1246)
        ++_failed_requests;
        if (_destroy_answers != 0) {
            // Pushed from inside the answer of such a push: refused by the return value alone, as connect() is, and its callback
            // destroyed unheard. There is no later turn to hear it on, and answered here a callback that always pushes again
            // was called from inside its own push without end.
            return false;
        }
        const auto *const text = _auto_reconnect ? "HTTP/1.1 client no longer available" : "HTTP/1.1 client is not connected";
        ++_destroy_answers;
        invoke_user_callback([&] { callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, text)); });
        --_destroy_answers;
        return true;
    }
    if (auto error = prepare_request(request)) {
        ++_failed_requests;
        refuse([callback = std::move(callback), response = std::move(*error)]() mutable { callback(std::move(response)); });
        return true;
    }
    if (_pending_requests.size() + (_active_request ? 1u : 0u) >= _max_pending_requests) {
        ++_failed_requests;
        refuse([this, callback = std::move(callback)]() mutable { // run by this client, alive: a hold's turn, or its destructor
            callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "HTTP/1.1 client pending request limit reached"));
        });
        return false;
    }
    auto ctx              = std::make_unique<RequestContext>();
    ctx->request_id       = _next_request_id++;
    ctx->request          = std::move(request);
    ctx->callback         = std::move(callback);
    ctx->created_at       = std::chrono::steady_clock::now();
    const auto request_id = ctx->request_id;
    _pending_requests.emplace_back(std::move(ctx));
    arm_pending_timeout(request_id);
    process_pending_requests();
    return true;
}

qb::http::async::awaiter<qb::http::Response>
Client::push_request(qb::http::Request request) {
    auto weak_self = weak_from_this();
    return qb::http::async::make_awaiter<qb::http::Response>(
        [weak_self, req = std::move(request)](std::function<void(qb::http::Response &&)> complete) mutable {
            auto self = weak_self.lock();
            if (!self) {
                qb::http::Response response;
                response.status() = qb::http::status::SERVICE_UNAVAILABLE;
                response.body()   = "HTTP/1.1 client no longer available";
                complete(std::move(response));
                return;
            }
            // Refused by its return value alone -- pushed from inside an answer the destructor's close delivers --, the push
            // never calls its callback: the awaiter completes here.
            auto answered = std::make_shared<bool>(false);
            if (!self->push_request(std::move(req),
                                    [complete, answered](qb::http::Response response) mutable {
                                        *answered = true;
                                        complete(std::move(response));
                                    })
                && !*answered && self->_destroying) {
                complete(self->create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "HTTP/1.1 client no longer available"));
            }
        });
}

bool
Client::push_requests(std::vector<qb::http::Request> requests, BatchResponseCallback callback) {
    if (!callback) {
        return false;
    }
    if (requests.empty()) {
        invoke_user_callback([&] { callback({}); });
        return true;
    }
    if (_destroying && _destroy_answers != 0) {
        _total_requests += requests.size();
        _failed_requests += requests.size();
        return false; // as push_request() there: refused by the return value alone, the batch's callback unheard
    }
    const auto batch_id = _next_batch_id++;
    auto       batch    = std::make_unique<BatchRequestContext>();
    batch->callback     = std::move(callback);
    batch->responses.resize(requests.size());
    _active_batches.emplace(batch_id, std::move(batch));

    bool queued_all = true;
    for (std::size_t i = 0; i < requests.size(); ++i) {
        queued_all = push_request(std::move(requests[i]),
                                  [this, batch_id, index = i](qb::http::Response response) {
                                      auto it = _active_batches.find(batch_id);
                                      if (it == _active_batches.end()) {
                                          return;
                                      }
                                      auto &batch_ref            = *it->second;
                                      batch_ref.responses[index] = std::move(response);
                                      if (++batch_ref.completed_count == batch_ref.responses.size()) {
                                          auto done = std::move(batch_ref.responses);
                                          auto cb   = std::move(batch_ref.callback);
                                          _active_batches.erase(it);
                                          if (cb) {
                                              invoke_user_callback([&] { cb(std::move(done)); });
                                          }
                                      }
                                  })
                     && queued_all;
    }
    return queued_all;
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
            const bool unheard = self->_destroying && self->_destroy_answers != 0; // refused by the return value alone: see push_request()
            self->push_requests(std::move(reqs),
                                [complete](std::vector<qb::http::Response> responses) mutable { complete(std::move(responses)); });
            if (unheard) {
                complete({});
            }
        });
}

void
Client::process_pending_requests() {
    if (_active_request || _pending_requests.empty()) {
        return;
    }
    if (!_is_connected || !_connection || !_connection->is_open()) {
        // An explicitly accepted connect owns these requests even when automatic
        // reconnect is disabled, including an intent waiting behind retirement.
        if (_is_connecting) {
            return;
        }
        if (!_auto_reconnect) {
            if (answers_wait_a_turn()) {
                _late_process = true; // pushed from one of this client's callbacks: the queue fails on the loop's next turn
                return;
            }
            fail_all_requests("HTTP/1.1 client is not connected");
            return;
        }
        if (!connect(nullptr)) {
            fail_all_requests("HTTP/1.1 client no longer available");
        }
        return;
    }
    _active_request = std::move(_pending_requests.front());
    _pending_requests.pop_front();
    _connection->send(_active_request->request, _request_timeout);
    if (!_active_request) {
        process_pending_requests();
    }
}

void
Client::hold_through_current_tick() {
    auto self = weak_from_this().lock();
    if (!self) {
        return; // no owner, nothing to hold: ~Client, or a client built without make_client() -- hence the owner, not `_destroying`
    }
    // Defer to the tail of this loop turn (not a magic 1µs timer): once the current
    // user callback has fully unwound, reset the deferred connection and drop the
    // self-hold. defer() runs after the dispatch, never inline.
    //
    // The self-hold lives in the CLOSURE, not in a member. That is the whole point: a
    // deferred callback is not guaranteed to run. `listener::clear()` drops the pending
    // queue outright, and a caller that simply stops turning the loop after its last
    // callback (three cases in tests/system/http1/http1-client.cpp do exactly that, and
    // it is legitimate — the client's contract does not promise another turn) leaves it
    // queued forever. A `std::shared_ptr<Client>` member released only by that callback
    // is therefore a self-referential cycle that nothing collects: the Client, its
    // connection, and the protocol `switch_protocol()` allocated all leak. LeakSanitizer
    // named it precisely — 15 blocks, every one of them *Indirect*, no Direct leak at all,
    // which is the signature of a cycle whose only inbound pointer is its own.
    //
    // Owned by the closure, both endings reclaim it: the callback runs and the closure is
    // destroyed, or the closure is destroyed unrun when the queue is dropped. It also
    // makes the hold provably sufficient — the Client cannot expire before the callback,
    // so there is no lock()-or-give-up path left to reason about.
    qb::io::async::defer(tick_hold{std::move(self)});
}

bool
Client::answers_wait_a_turn() const noexcept {
    // A turn exists to wait for only while a hold can be queued for it: not for a client being destroyed, nor for one with no
    // shared owner.
    return _callback_depth != 0 && !_destroying && !weak_from_this().expired();
}

void
Client::refuse(std::function<void()> answer) {
    if (!answers_wait_a_turn()) {
        invoke_user_callback(answer);
        return;
    }
    // Heard by the hold that runs once this callback has returned (tick_hold; leave_user_callback() queues one when the
    // callback's own was drained under it).
    _late_answers.push_back(std::move(answer));
}

void
Client::run_late_answers() {
    if (_callback_depth != 0) {
        return; // drained under a callback: the hold queued when it returns delivers
    }
    // Taken first: what one of them pushes is kept for the next turn, not this one.
    auto       answers = std::exchange(_late_answers, {});
    const bool process = std::exchange(_late_process, false);
    for (auto &answer : answers) {
        invoke_user_callback(answer);
    }
    if (process && !_destroying) {
        process_pending_requests();
    }
}

void
Client::enter_user_callback() {
    ++_callback_depth;
    hold_through_current_tick();
}

void
Client::leave_user_callback() noexcept {
    if (_callback_depth && --_callback_depth == 0 && _holds_queued == 0) [[unlikely]] {
        // A pump the callback ran -- run_sync() of a coroutine, a loop turn of its own -- drained the hold its entry queued
        // while the callback was still on the stack: that hold gave up a retirement it found under a callback, and it no
        // longer keeps this client. One more, now that no callback is: for the retirement, and for the client itself --
        // on a connection that is kept, a callback that then dropped the last reference destroyed the client, and its
        // connection with it, under that connection's own read pass (Huly QB-1246).
        try {
            hold_through_current_tick();
        } catch (...) {
            // An allocation failed: the retirement waits for the hold of the next callback.
        }
    }
}

void
Client::reset_deferred_connection_if_ready() {
    if (_callback_depth || !_deferred_connection_reset) {
        return;
    }
    const bool start_connection = _is_connecting;
    _connection.reset();
    _deferred_connection_reset = false;
    if (start_connection) {
        _is_connecting = false;
        connect(nullptr);
    } else if (!_intentional_disconnect) {
        process_pending_requests(); // a backstop: every close settles its queue inside itself, so nothing is left here to fail (QB-1246)
    }
}

void
Client::retire_connection(bool defer_cleanup) {
    _is_connected  = false;
    _is_connecting = false;
    if (_deferred_connection_reset) {
        return;
    }
    _deferred_connection_reset = true;
    if (_connection) {
        _connection->disconnect();
    }
    if (defer_cleanup) {
        hold_through_current_tick();
    }
}

Client::failure_cohort
Client::detach_failure_cohort(bool fail_pending) {
    failure_cohort cohort;
    cohort.active = std::move(_active_request);
    if (fail_pending && !_pending_requests.empty()) {
        cohort.pending.emplace(std::move(_pending_requests));
        _pending_requests.clear();
    }
    cohort.callbacks = std::move(_connection_callbacks);
    _connection_callbacks.clear();
    return cohort;
}

void
Client::fail_retired_requests(failure_cohort &cohort, std::string const &error, qb::http::status active_status,
                              std::string const &pending_error, qb::http::status pending_status) {
    for (auto &callback : cohort.callbacks) {
        if (callback) {
            invoke_user_callback([&] { callback(false, error); });
        }
    }
    if (cohort.active) {
        auto ctx = std::move(cohort.active);
        ++_failed_requests;
        invoke_user_callback([&] { ctx->callback(create_error_response(active_status, error)); });
    }
    if (cohort.pending) {
        while (!cohort.pending->empty()) {
            auto ctx = std::move(cohort.pending->front());
            cohort.pending->pop_front();
            ++_failed_requests;
            invoke_user_callback([&] { ctx->callback(create_error_response(pending_status, pending_error)); });
        }
    }
}

void
Client::arm_pending_timeout(std::uint64_t request_id) {
    if (_destroying || _request_timeout <= qb::duration::zero()) {
        return; // nothing is armed for a client being destroyed: after its thread's loop a timer stops the process (Huly QB-1246)
    }
    auto weak_self = weak_from_this();
    qb::io::async::callback(
        [weak_self, request_id]() {
            auto self = weak_self.lock();
            if (!self) {
                return;
            }
            if (self->fail_pending_request(request_id, "HTTP/1.1 request timeout while pending", qb::http::status::REQUEST_TIMEOUT)) {
                self->process_pending_requests();
            }
        },
        _request_timeout);
}

bool
Client::fail_pending_request(std::uint64_t request_id, std::string const &error, qb::http::status status) {
    auto self_guard = weak_from_this().lock();
    for (auto it = _pending_requests.begin(); it != _pending_requests.end(); ++it) {
        if (!*it || (*it)->request_id != request_id) {
            continue;
        }
        auto ctx = std::move(*it);
        _pending_requests.erase(it);
        ++_failed_requests;
        invoke_user_callback([&] { ctx->callback(create_error_response(status, error)); });
        return true;
    }
    return false;
}

void
Client::handle_connection_success() {
    if (_deferred_connection_reset) {
        return;
    }
    auto self_guard         = weak_from_this().lock();
    _is_connected           = true;
    _is_connecting          = false;
    _intentional_disconnect = false;
    auto callbacks          = std::move(_connection_callbacks);
    _connection_callbacks.clear();
    for (auto &cb : callbacks) {
        if (cb) {
            invoke_user_callback([&] { cb(true, ""); });
        }
    }
    if (_intentional_disconnect) {
        return;
    }
    process_pending_requests();
}

void
Client::handle_connection_failure(std::string const &error) {
    if (_deferred_connection_reset) {
        return;
    }
    auto self_guard = weak_from_this().lock();
    auto cohort     = detach_failure_cohort(true);
    retire_connection();
    fail_retired_requests(cohort, error, qb::http::status::BAD_GATEWAY, error, qb::http::status::SERVICE_UNAVAILABLE);
}

void
Client::handle_response(qb::http::Response response) {
    auto self_guard = weak_from_this().lock();
    if (!_active_request) {
        return;
    }
    auto       ctx        = std::move(_active_request);
    const bool keep_alive = response.keep_alive && !has_connection_close(response);
    ++_successful_requests;
    if (keep_alive) {
        invoke_user_callback([&] { ctx->callback(std::move(response)); });
        if (!_intentional_disconnect) {
            process_pending_requests();
        }
        return;
    }
    // Availability and retirement are published before user code can submit the next request; neither the transport nor
    // the parser on this stack is replaced here. The queue is settled inside this close, the connection still retired --
    // a connection asked for it with automatic reconnection, failed without --, never by the reset the loop's deferred
    // queue runs later: no close is under way there, and a connect() awaited from a callback could not complete (QB-1246).
    retire_connection();
    invoke_user_callback([&] { ctx->callback(std::move(response)); });
    if (!_intentional_disconnect) {
        process_pending_requests();
    }
}

void
Client::handle_timeout() {
    if (_deferred_connection_reset) {
        return;
    }
    if (_is_connecting && !_is_connected) {
        handle_connection_failure("Connection timeout");
        return;
    }
    auto self_guard = weak_from_this().lock();
    auto cohort     = detach_failure_cohort(!_auto_reconnect);
    retire_connection();
    fail_retired_requests(cohort, "Request timeout", qb::http::status::GATEWAY_TIMEOUT, "Connection lost",
                          qb::http::status::SERVICE_UNAVAILABLE);
    if (!_intentional_disconnect) {
        process_pending_requests(); // the queue kept for reconnection, settled inside the close: a callback may have ended that (QB-1246)
    }
}

void
Client::handle_disconnected(int reason, std::string const &cut) {
    if (_deferred_connection_reset) {
        return;
    }
    auto       self_guard = weak_from_this().lock();
    const auto error      = !cut.empty() ? cut : std::string(_intentional_disconnect || reason != 0 ? "Connection closed" : "Connection lost");
    auto       cohort     = detach_failure_cohort(!_auto_reconnect);
    // Retired before any callback, a cut response's included: what one pushes is for the next connection, never this one (QB-1248).
    retire_connection();
    fail_retired_requests(cohort, error, qb::http::status::BAD_GATEWAY, "Connection lost", qb::http::status::SERVICE_UNAVAILABLE);
    if (!_intentional_disconnect) {
        process_pending_requests(); // as after a timeout: the queue settled inside the close (QB-1246)
    }
}

void
Client::fail_active_request(std::string const &error, qb::http::status status) {
    auto self_guard = weak_from_this().lock();
    if (!_active_request) {
        return;
    }
    std::shared_ptr<RequestContext> ctx = std::move(_active_request);
    ++_failed_requests;
    // Through refuse(): a request that cannot be sent fails inside the push that sent it, where its callback may push it back.
    refuse([ctx, response = create_error_response(status, error)]() mutable { ctx->callback(std::move(response)); });
}

void
Client::fail_all_requests(std::string const &error, qb::http::status status) {
    auto self_guard = weak_from_this().lock();
    auto pending    = std::move(_pending_requests);
    _pending_requests.clear();
    while (!pending.empty()) {
        auto ctx = std::move(pending.front());
        pending.pop_front();
        ++_failed_requests;
        invoke_user_callback([&] { ctx->callback(create_error_response(status, error)); });
    }
}

bool
Client::has_pending_work() const noexcept {
    return _active_request || !_pending_requests.empty();
}

qb::http::Response
Client::create_error_response(qb::http::status status, std::string const &message) {
    qb::http::Response response;
    response.status() = status;
    response.body()   = message;
    response.set_header("content-type", "text/plain");
    response.set_header("content-length", std::to_string(response.body().raw().size()));
    response.keep_alive = false;
    return response;
}

std::shared_ptr<Client>
make_client(std::string const &base_uri) {
    return std::make_shared<Client>(base_uri);
}

std::shared_ptr<Client>
make_client(qb::io::uri const &uri) {
    return std::make_shared<Client>(uri);
}

// A 101 ends HTTP/1.1 on its connection (RFC 9110 section 15.2.2): what follows it is another protocol, which this client
// does not speak. The connection is retired, never handed the next request -- kept, it read the switched protocol's
// bytes as the next request's response (Huly QB-1248) -- and so is one that switches with no request in flight. A
// switch to what the request offered in its Upgrade field is its answer, delivered; any other, which a server must not
// send (section 7.8), fails it with 502, as a response the client cannot use. The queue goes to a new connection,
// with auto-reconnect (the default); without it, the queue fails as after any connection retired.
void
Client::handle_switched_protocols(qb::http::Response response) {
    auto self_guard = weak_from_this().lock();
    if (!_active_request) {
        retire_connection();
        if (!_intentional_disconnect) {
            process_pending_requests(); // inside the close, as every close settles its queue (QB-1246)
        }
        return;
    }
    if (!qb::http::detail::switch_was_offered(_active_request->request, response)) {
        retire_connection(); // published before user code can submit the next request, as handle_response() does
        fail_active_request("HTTP/1.1 server switched to a protocol the request did not offer", qb::http::status::BAD_GATEWAY);
        if (!_intentional_disconnect) {
            process_pending_requests(); // the queue settled inside the close, as handle_response() settles it (QB-1246)
        }
        return;
    }
    response.keep_alive = false;
    handle_response(std::move(response));
}

/// The limits the protocol reads as each response begins (its `http_request_limits()` hook, the server's own name): the
/// defaults, the body's set_max_body_size() -- 0, none (Huly QB-1248).
template <typename Transport>
qb::http::request_limits
Client::connection<Transport>::http_request_limits() const noexcept {
    qb::http::request_limits limits;
    limits.max_body_size = _owner.max_body_size();
    return limits;
}

} // namespace qb::http1

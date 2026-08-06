/**
 * @file qbm/http/1.1/client.cpp
 * @brief Implementation of the persistent HTTP/1.1 client.
 *
 * Contains the out-of-line definitions for `qb::http1::Client` (connection
 * lifecycle, request queueing/dispatch, timeout and reconnection handling,
 * batch coordination, and the coroutine awaiter factories) together with the
 * private `connection<Transport>` adapter that bridges the client to qb-io's
 * asynchronous TCP/TLS transports.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./client.h"

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <utility>

#include <qb/io/async/tcp/connector.h>
#include <qb/io/transport/tcp.h>
#ifdef QB_HAS_SSL
#include <qb/io/transport/stcp.h>
#endif

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

    /// Typed protocol handle, captured from switch_protocol so on(disconnected) can flush a
    /// close-delimited response body (no Content-Length / Transfer-Encoding) that the parser
    /// buffered until EOF. Owned by the io base's protocol list; not freed here.
    http_protocol *_http_protocol = nullptr;

    explicit connection(Client &owner)
        : _owner(owner) {
        _http_protocol = this->template switch_protocol<http_protocol>(*this);
        this->setTimeout(qb::duration::zero());
    }

    ~connection() override {
        *_alive = false;
    }

    [[nodiscard]] bool
    http1_response_body_forbidden() const noexcept {
        return _active_method == qb::http::Method::HEAD;
    }

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
        auto owner_guard = _owner.weak_from_this().lock();
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
        // A close-delimited response (no Content-Length, no Transfer-Encoding) is framed by the
        // connection close: deliver its buffered body NOW, before the disconnect tears the active
        // request down. flush_eof dispatches through on(response) → handle_response, completing
        // the request, so handle_disconnected below then finds nothing to fail. No-op otherwise.
        if (_http_protocol) {
            _http_protocol->flush_eof();
        }
        _owner.handle_disconnected(event.reason);
    }

    void
    on(qb::io::async::event::dispose const &) {}
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

template <typename Fn>
void
Client::invoke_user_callback(Fn &&fn) noexcept {
    callback_scope scope(*this);
    try {
        fn();
    } catch (std::exception const &e) {
        LOG_HTTP_WARN("HTTP/1.1 client user callback threw: " << e.what());
    } catch (...) {
        LOG_HTTP_WARN("HTTP/1.1 client user callback threw an unknown exception");
    }
}

Client::Client(std::string const &base_uri)
    : Client(qb::io::uri(base_uri)) {}

Client::Client(qb::io::uri const &uri) {
    initialize_from_uri(uri);
}

Client::~Client() {
    disconnect();
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
    if (_is_connected) {
        if (callback) {
            callback_scope scope(*this);
            callback(true, "");
        }
        return true;
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
            // `complete` was MOVED into the connect callback above. On this path connect()
            // declined to start (already connected, already connecting, or unable to start) and
            // never took ownership — but the std::function here is already empty, so calling it
            // throws std::bad_function_call and the awaiter never receives its ConnectResult.
            // Hand the lambda a COPY so the fallback below still has a live callable. The copy
            // costs one std::function allocation on a connection attempt: a cold path.
        if (!self->connect([complete](bool ok, std::string const &err) mutable { complete(ConnectResult{ok, err}); })) {
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

void
Client::disconnect() {
    _intentional_disconnect = true;
    _is_connected           = false;
    _is_connecting          = false;
    fail_active_request("Connection closed", qb::http::status::SERVICE_UNAVAILABLE);
    fail_all_requests("Connection closed", qb::http::status::SERVICE_UNAVAILABLE);
    if (_connection) {
        _connection->disconnect();
    }
    if (_callback_depth) {
        _deferred_connection_reset = true;
    } else {
        _connection.reset();
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
    if (auto error = prepare_request(request)) {
        ++_failed_requests;
        invoke_user_callback([&] { callback(std::move(*error)); });
        return true;
    }
    if (_pending_requests.size() + (_active_request ? 1u : 0u) >= _max_pending_requests) {
        ++_failed_requests;
        invoke_user_callback(
            [&] { callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "HTTP/1.1 client pending request limit reached")); });
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
            self->push_request(std::move(req),
                               [complete = std::move(complete)](qb::http::Response response) mutable { complete(std::move(response)); });
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
            self->push_requests(std::move(reqs), [complete = std::move(complete)](std::vector<qb::http::Response> responses) mutable {
                complete(std::move(responses));
            });
        });
}

void
Client::process_pending_requests() {
    if (_active_request || _pending_requests.empty()) {
        return;
    }
    if (!_is_connected || !_connection || !_connection->is_open()) {
        if (!_auto_reconnect) {
            auto ctx = std::move(_pending_requests.front());
            _pending_requests.pop_front();
            ++_failed_requests;
            invoke_user_callback(
                [&] { ctx->callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "HTTP/1.1 client is not connected")); });
            process_pending_requests();
            return;
        }
        if (!_is_connecting) {
            connect(nullptr);
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
        return; // called from ~Client: the control block is already at zero, nothing to hold
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
    qb::io::async::defer([self = std::move(self)]() mutable {
        self->reset_deferred_connection_if_ready();
        self.reset();
    });
}

void
Client::enter_user_callback() {
    ++_callback_depth;
    hold_through_current_tick();
}

void
Client::leave_user_callback() noexcept {
    if (_callback_depth) {
        --_callback_depth;
    }
}

void
Client::reset_deferred_connection_if_ready() {
    if (_callback_depth || !_deferred_connection_reset) {
        return;
    }
    _deferred_connection_reset = false;
    _connection.reset();
}

void
Client::arm_pending_timeout(std::uint64_t request_id) {
    if (_request_timeout <= qb::duration::zero()) {
        return;
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
    auto self_guard = weak_from_this().lock();
    _is_connected   = false;
    _is_connecting  = false;
    auto callbacks  = std::move(_connection_callbacks);
    _connection_callbacks.clear();
    for (auto &cb : callbacks) {
        if (cb) {
            invoke_user_callback([&] { cb(false, error); });
        }
    }
    if (_active_request) {
        fail_active_request(error);
    }
    fail_all_requests(error);
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
    invoke_user_callback([&] { ctx->callback(std::move(response)); });
    if (_intentional_disconnect) {
        return;
    }
    if (!keep_alive) {
        _is_connected = false;
        // Tear the connection down but DO NOT reconnect synchronously here: handle_response runs
        // INSIDE the protocol's onMessage(), which reset()s the parser right after we return.
        // qb::io::async::callback() executes its lambda IMMEDIATELY (not next-tick), so a reconnect
        // here would create_connection() and free THIS connection's protocol mid-dispatch → a
        // heap-use-after-free when onMessage() then touches the freed parser. The reconnect for
        // still-pending work is owned by the ensuing on(disconnected) → handle_disconnected (a
        // fresh, safe dispatch), exactly as for an unexpected server-side close.
        if (_connection) {
            _connection->disconnect();
        }
        return;
    }
    process_pending_requests();
}

void
Client::handle_timeout() {
    if (_is_connecting && !_is_connected) {
        handle_connection_failure("Connection timeout");
        return;
    }
    fail_active_request("Request timeout", qb::http::status::GATEWAY_TIMEOUT);
    if (_connection) {
        _connection->disconnect();
    }
}

void
Client::handle_disconnected(int reason) {
    const bool intentional = _intentional_disconnect || reason != 0;
    _is_connected          = false;
    _is_connecting         = false;
    if (_active_request) {
        fail_active_request(intentional ? "Connection closed" : "Connection lost");
    }
    if (_intentional_disconnect) {
        return;
    }
    if (has_pending_work() && _auto_reconnect) {
        auto weak_self = weak_from_this();
        // Defer, do NOT reconnect inline. handle_disconnected() runs inside the connection's
        // on(disconnected) → io::dispose() dispatch; create_connection() below reassigns _connection
        // and frees THIS connection, so running it synchronously is a use-after-free once dispose()
        // resumes. defer() posts it to the tail of the loop turn — it runs only after the whole
        // dispatch has unwound, so the connection is no longer on the stack.
        qb::io::async::defer([weak_self]() {
            auto self = weak_self.lock();
            if (!self || self->_is_connected || self->_is_connecting || !self->has_pending_work()) {
                return;
            }
            self->create_connection();
            self->connect(nullptr);
        });
    } else if (has_pending_work()) {
        fail_all_requests("Connection lost");
    }
}

void
Client::fail_active_request(std::string const &error, qb::http::status status) {
    auto self_guard = weak_from_this().lock();
    if (!_active_request) {
        return;
    }
    auto ctx = std::move(_active_request);
    ++_failed_requests;
    invoke_user_callback([&] { ctx->callback(create_error_response(status, error)); });
}

void
Client::fail_all_requests(std::string const &error, qb::http::status status) {
    auto self_guard = weak_from_this().lock();
    while (!_pending_requests.empty()) {
        auto ctx = std::move(_pending_requests.front());
        _pending_requests.pop_front();
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

} // namespace qb::http1

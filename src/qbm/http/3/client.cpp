/**
 * @file qbm/http/3/client.cpp
 * @brief HTTP/3 client implementation.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "client.h"

#include <algorithm>

#include <nghttp3/nghttp3.h>

#include "../origin.h"

namespace qb::http3 {

namespace {
// Endpoint dispatch continues after a derived callback returns. If user code
// releases the last external owner, defer the last reference until the next
// listener turn, after the endpoint's outer event handler has unwound.
struct EventLifetime {
    std::shared_ptr<Client> owner;

    explicit EventLifetime(Client &client)
        : owner(client.weak_from_this().lock()) {}

    ~EventLifetime() {
        if (owner && owner.use_count() == 1) {
            qb::io::async::listener::current.defer([hold = std::move(owner)] {});
        }
    }
};
} // namespace

Client::Client(std::string const &base_uri)
    : _client_id(qb::generate_random_uuid()) {
    initialize_from_uri(qb::io::uri(base_uri));
}

Client::Client(qb::io::uri const &uri)
    : _client_id(qb::generate_random_uuid()) {
    initialize_from_uri(uri);
}

Client::~Client() {
    try {
        (void) fail_all_requests("HTTP/3 client destroyed");
    } catch (...) {
        // A destructor cannot propagate an application callback's exception.
    }
    try {
        disconnect();
    } catch (...) {
        // Complete object destruction even if closing reports an exception.
    }
}

void
Client::initialize_from_uri(qb::io::uri const &uri) {
    if (!qb::http::origin::scheme_eq(uri.scheme(), "https")) {
        throw std::invalid_argument("HTTP/3 client only supports https scheme");
    }
    _base_uri = uri;
    _host     = std::string(uri.host());
}

void
Client::set_verify_peer(bool value) noexcept {
    _verify_peer = value;
}

bool
Client::connect(ConnectionCallback callback) {
    auto owner = weak_from_this().lock();
    if (_deferred_close && (_read_depth > 0 || _deferred_close->empty())) {
        // The old connection is still on nghttp3's stack. A new handshake must
        // wait until its teardown has completed after the outer read.
        if (callback) {
            callback(false, "HTTP/3 connection is closing");
        }
        return false;
    }
    if (_is_connected) {
        if (callback) {
            callback(true, {});
        }
        return true;
    }
    if (_is_connecting) {
        if (callback) {
            _connection_callbacks.push_back(std::move(callback));
        }
        return true;
    }
    if (callback) {
        _connection_callbacks.push_back(std::move(callback));
    }
    ++_connect_epoch;
    _is_connecting   = true;
    _h3_ready        = false;
    _remote_shutdown = false;

    qb::io::quic::tls_config tls;
    tls.server_name = _host;
    tls.verify_peer = _verify_peer;
    if (!qb::io::async::quic::endpoint::connect(_base_uri, std::move(tls), {"h3"})) {
        close_failed_transport("Unable to start QUIC connection");
        handle_connection_failure("Unable to start QUIC connection");
        return false;
    }
    arm_connect_timeout();
    return true;
}

void
Client::disconnect() {
    if (_deferred_close && _deferred_close->empty()) {
        return; // an explicit close is already notifying its old requests
    }
    if (_read_depth > 0 || _submit_depth > 0) {
        // A pending callback may call disconnect from nghttp3_conn_read_stream2.
        // Keep _h3 alive until that native reader returns. An empty deferred
        // reason marks explicit intent and takes precedence over a transport
        // close, so the outer dispatch will not start an automatic reconnect.
        ++_connect_epoch;
        _is_connected    = false;
        _is_connecting   = false;
        _h3_ready        = false;
        _remote_shutdown = true;
        _deferred_close.emplace();
        return;
    }
    // Mark the old connection unavailable before invoking failure callbacks.
    // They may call connect(), push_request(), or disconnect() again.
    auto owner = weak_from_this().lock();
    ++_connect_epoch;
    _is_connected    = false;
    _is_connecting   = false;
    _h3_ready        = false;
    _remote_shutdown = true;
    _deferred_close.emplace();
    auto callbacks = std::move(_connection_callbacks);
    _connection_callbacks.clear();
    std::exception_ptr callback_error;
    const auto         capture = [&](auto &&notify) {
        try {
            notify();
        } catch (...) {
            if (!callback_error) {
                callback_error = std::current_exception();
            }
        }
    };
    for (auto &callback : callbacks) {
        if (callback) {
            capture([&] { callback(false, "HTTP/3 client disconnect"); });
        }
    }
    if (auto error = fail_all_requests("HTTP/3 client disconnect"); error && !callback_error) {
        callback_error = error;
    }
    _h3.reset();
    capture([&] { qb::io::async::quic::endpoint::close(0, "HTTP/3 client disconnect"); });
    _deferred_close.reset();
    _remote_shutdown = false;
    if (callback_error) {
        std::rethrow_exception(callback_error);
    }
}

void
Client::ensure_absolute_uri(qb::http::Request &request) {
    if (!request.uri().host().empty()) {
        return;
    }
    std::string absolute = "https://" + std::string(_base_uri.host());
    if (!_base_uri.port().empty()) {
        absolute.push_back(':');
        absolute += _base_uri.port();
    }
    absolute += request.uri().path().empty() ? "/" : std::string(request.uri().path());
    if (!request.uri().encoded_queries().empty()) {
        absolute.push_back('?');
        absolute += request.uri().encoded_queries();
    }
    request.uri() = qb::io::uri(absolute);
}

std::optional<qb::http::Response>
Client::prepare_request(qb::http::Request &request) {
    ensure_absolute_uri(request);
    if (request.uri().host().empty()) {
        return create_error_response(qb::http::status::BAD_REQUEST, "HTTP/3 request URI is missing a host");
    }
    if (!qb::http::origin::scheme_eq(request.uri().scheme(), "https")) {
        return create_error_response(qb::http::status::BAD_REQUEST, "HTTP/3 request URI must use https");
    }
    if (!qb::http::origin::same(request.uri(), _base_uri)) {
        return create_error_response(qb::http::status::BAD_REQUEST, "HTTP/3 persistent client only accepts same-origin requests");
    }
    return std::nullopt;
}

bool
Client::push_request(qb::http::Request request, ResponseCallback callback) {
    if (!callback) {
        return false;
    }
    (void) push_request_with_id(std::move(request), std::move(callback));
    return true;
}

request_id
Client::push_request_with_id(qb::http::Request request, ResponseCallback callback) {
    if (!callback) {
        return 0;
    }
    ++_total_requests;
    if (auto error = prepare_request(request)) {
        ++_failed_requests;
        callback(std::move(*error));
        return 0;
    }
    if (_remote_shutdown) {
        ++_failed_requests;
        const auto *reason = _deferred_close && _deferred_close->empty() ? "HTTP/3 client disconnect" : "HTTP/3 server is shutting down";
        callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, reason));
        return 0;
    }
    if (_pending_requests.size() + _active_requests.size() >= _max_pending_requests) {
        ++_failed_requests;
        callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "HTTP/3 client pending request limit reached"));
        return 0;
    }
    auto ctx              = std::make_unique<RequestContext>();
    ctx->request          = std::move(request);
    ctx->callback         = std::move(callback);
    ctx->created_at       = std::chrono::steady_clock::now();
    ctx->request_id       = _next_request_id++;
    const auto request_id = ctx->request_id;
    _pending_requests.push_back(std::move(ctx));
    arm_request_timeout(request_id);

    if (is_connected()) {
        process_pending_requests();
    } else if (!_is_connecting) {
        connect(nullptr);
    }
    return request_id;
}

bool
Client::cancel_request(request_id id, std::string const &reason) {
    auto pending =
        std::find_if(_pending_requests.begin(), _pending_requests.end(), [id](auto const &ctx) { return ctx && ctx->request_id == id; });
    if (pending != _pending_requests.end()) {
        auto ctx = std::move(*pending);
        _pending_requests.erase(pending);
        ++_failed_requests;
        ctx->callback(create_error_response(qb::http::status::CLIENT_CLOSED_REQUEST, reason));
        return true;
    }

    auto active = std::find_if(_active_requests.begin(), _active_requests.end(),
                               [id](auto const &entry) { return entry.second && entry.second->request_id == id; });
    if (active == _active_requests.end()) {
        return false;
    }
    const auto stream_id = active->first;
    auto       owner     = weak_from_this().lock(); // Keep alive through callback and RFC 9114 §4.1 stream reset.
    fail_request(stream_id, reason, qb::http::status::CLIENT_CLOSED_REQUEST);
    reset_stream(0, stream_id, NGHTTP3_H3_REQUEST_CANCELLED);
    process_pending_requests();
    return true;
}

bool
Client::push_requests(std::vector<qb::http::Request> requests, BatchResponseCallback callback) {
    if (requests.empty()) {
        if (callback) {
            callback({});
        }
        return true;
    }
    if (!callback) {
        return false;
    }
    if (_remote_shutdown) {
        std::vector<qb::http::Response> responses;
        responses.reserve(requests.size());
        const auto *reason = _deferred_close && _deferred_close->empty() ? "HTTP/3 client disconnect" : "HTTP/3 server is shutting down";
        for (std::size_t i = 0; i < requests.size(); ++i) {
            responses.push_back(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, reason));
        }
        _total_requests += requests.size();
        _failed_requests += requests.size();
        callback(std::move(responses));
        return true;
    }

    const auto batch_id = _next_batch_id++;
    auto       batch    = std::make_unique<BatchRequestContext>();
    batch->callback     = std::move(callback);
    batch->responses.resize(requests.size());
    batch->completed.assign(requests.size(), false);

    _total_requests += requests.size();

    for (std::size_t i = 0; i < requests.size(); ++i) {
        if (auto error = prepare_request(requests[i])) {
            ++_failed_requests;
            batch->responses[i] = std::move(*error);
            batch->completed[i] = true;
            ++batch->completed_count;
            continue;
        }
        auto ctx              = std::make_unique<RequestContext>();
        ctx->request          = std::move(requests[i]);
        ctx->created_at       = std::chrono::steady_clock::now();
        ctx->request_id       = _next_request_id++;
        ctx->batch_id         = batch_id;
        const auto request_id = ctx->request_id;
        ctx->callback         = [this, batch_id, i](qb::http::Response response) {
            auto it = _active_batches.find(batch_id);
            if (it == _active_batches.end()) {
                return;
            }
            auto &batch_ctx        = *it->second;
            batch_ctx.responses[i] = std::move(response);
            batch_ctx.completed[i] = true;
            if (++batch_ctx.completed_count == batch_ctx.responses.size()) {
                auto done      = std::move(batch_ctx.callback);
                auto responses = std::move(batch_ctx.responses);
                _active_batches.erase(it);
                done(std::move(responses));
            }
        };
        _pending_requests.push_back(std::move(ctx));
        arm_request_timeout(request_id);
    }

    if (batch->completed_count == batch->responses.size()) {
        // Call through `batch->callback`, NOT `callback`: ownership moved to the batch above, so
        // `callback` is an empty std::function here and invoking it throws std::bad_function_call.
        // Reached whenever every request in the batch fails prepare_request synchronously (a batch
        // of malformed URIs), i.e. exactly when the caller most needs its error results.
        batch->callback(std::move(batch->responses));
        return true;
    }

    _active_batches.emplace(batch_id, std::move(batch));

    if (is_connected()) {
        process_pending_requests();
    } else if (!_is_connecting) {
        connect(nullptr);
    }
    return true;
}

void
Client::process_pending_requests() {
    auto owner = weak_from_this().lock();
    if (!_h3 || !is_connected() || _remote_shutdown) {
        return;
    }
    while (_h3 && is_connected() && !_remote_shutdown && !_pending_requests.empty() && _active_requests.size() < _max_concurrent_streams) {
        // A prior iteration's submit_request / reset_stream drains output; a >TX-cap send can
        // have reentrantly scheduled a connection teardown (deferred until the read unwinds —
        // see dispatch(stream_data)). Stop enqueuing onto a connection that is going away: the
        // deferred fail_all_requests will fail everything already in _active_requests. Checking
        // at the loop top covers BOTH the submit-success and the submit-failure (reset_stream)
        // paths below, either of which can set _deferred_close.
        if (_deferred_close) {
            return;
        }
        auto ctx = std::move(_pending_requests.front());
        _pending_requests.pop_front();

        auto stream              = open_bidirectional_stream(0);
        ctx->stream_id           = stream.id();
        const auto stream_id     = ctx->stream_id;
        const auto attempt_epoch = _connect_epoch;
        bool       submitted     = false;
        {
            struct SubmitGuard {
                int &depth;
                explicit SubmitGuard(int &value) noexcept
                    : depth(value) {
                    ++depth;
                }
                ~SubmitGuard() noexcept {
                    --depth;
                }
            } guard(_submit_depth);
            submitted = _h3->submit_request(stream_id, ctx->request);
        }
        std::exception_ptr transition_error;
        bool               closed_during_submit = false;
        if (_deferred_close && _read_depth == 0 && _submit_depth == 0) {
            closed_during_submit     = true;
            const std::string reason = std::move(*_deferred_close);
            _deferred_close.reset();
            try {
                if (reason.empty()) {
                    disconnect();
                } else {
                    close_failed_transport("HTTP/3 connection closed");
                    handle_connection_failure(reason);
                    if (_auto_reconnect && has_pending_or_active_work()) {
                        connect(nullptr);
                    }
                }
            } catch (...) {
                transition_error = std::current_exception();
            }
        }
        if (closed_during_submit || attempt_epoch != _connect_epoch || !_h3 || !is_connected()) {
            ++_failed_requests;
            try {
                ctx->callback(
                    create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "HTTP/3 connection closed during request submission"));
            } catch (...) {
                if (!transition_error) {
                    transition_error = std::current_exception();
                }
            }
            if (transition_error) {
                std::rethrow_exception(transition_error);
            }
            return;
        }
        if (!submitted) {
            // Request never made it onto the wire; abandon the just-opened
            // stream the same way the client cancels any request (RFC 9114 §4.1).
            reset_stream(0, stream_id, NGHTTP3_H3_REQUEST_CANCELLED);
            ++_failed_requests;
            ctx->callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "Failed to submit HTTP/3 request"));
            continue;
        }
        _active_requests.emplace(stream_id, std::move(ctx));
    }
}

void
Client::handle_connection_success(std::string const &alpn) {
    ++_connect_epoch;
    _is_connected    = true;
    _is_connecting   = false;
    _h3_ready        = true;
    _remote_shutdown = false;
    _h3              = std::make_unique<h3_connection>(*this, 0, h3_connection::role::client);
    _h3->bind_local_streams();
    auto callbacks = std::move(_connection_callbacks);
    _connection_callbacks.clear();
    std::exception_ptr callback_error;
    for (auto &cb : callbacks) {
        if (cb) {
            try {
                cb(true, {});
            } catch (...) {
                if (!callback_error) {
                    callback_error = std::current_exception();
                }
            }
        }
    }
    process_pending_requests();
    LOG_HTTP_INFO_PA(_client_id, "HTTP/3 connected with ALPN " << alpn);
    if (callback_error) {
        std::rethrow_exception(callback_error);
    }
}

void
Client::handle_connection_failure(std::string const &error) {
    ++_connect_epoch;
    _is_connected    = false;
    _is_connecting   = false;
    _h3_ready        = false;
    _remote_shutdown = false;
    _h3.reset();
    auto callbacks = std::move(_connection_callbacks);
    _connection_callbacks.clear();
    // Retire old requests before connection callbacks can enqueue a new attempt.
    // fail_all_requests swaps its registries first, so work started by any of
    // its callbacks belongs to the next connection.
    auto callback_error = fail_all_requests(error);
    for (auto &cb : callbacks) {
        if (cb) {
            try {
                cb(false, error);
            } catch (...) {
                if (!callback_error) {
                    callback_error = std::current_exception();
                }
            }
        }
    }
    if (callback_error) {
        std::rethrow_exception(callback_error);
    }
}

void
Client::close_failed_transport(std::string_view reason) {
    struct CloseGuard {
        bool &flag;
        explicit CloseGuard(bool &value) noexcept
            : flag(value) {
            flag = true;
        }
        ~CloseGuard() noexcept {
            flag = false;
        }
    } guard(_closing_failed_attempt);
    qb::io::async::quic::endpoint::close(0, reason);
}

std::exception_ptr
Client::fail_all_requests(std::string const &error) {
    qb::unordered_map<std::uint64_t, std::unique_ptr<RequestContext>>      active;
    std::deque<std::unique_ptr<RequestContext>>                            pending;
    qb::unordered_map<std::uint64_t, std::unique_ptr<BatchRequestContext>> batches;
    active.swap(_active_requests);
    pending.swap(_pending_requests);
    batches.swap(_active_batches);
    std::exception_ptr callback_error;
    const auto         capture = [&](auto &&notify) {
        try {
            notify();
        } catch (...) {
            if (!callback_error) {
                callback_error = std::current_exception();
            }
        }
    };

    for (auto &[id, ctx] : active) {
        (void) id;
        if (ctx->batch_id != 0) {
            continue;
        }
        ++_failed_requests;
        capture([&] { ctx->callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, error)); });
    }
    while (!pending.empty()) {
        auto ctx = std::move(pending.front());
        pending.pop_front();
        if (ctx->batch_id != 0) {
            continue;
        }
        ++_failed_requests;
        capture([&] { ctx->callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, error)); });
    }
    for (auto &[id, batch] : batches) {
        (void) id;
        for (std::size_t i = 0; i < batch->responses.size(); ++i) {
            if (i >= batch->completed.size() || !batch->completed[i]) {
                ++_failed_requests;
                batch->responses[i] = create_error_response(qb::http::status::SERVICE_UNAVAILABLE, error);
            }
        }
        capture([&] { batch->callback(std::move(batch->responses)); });
    }
    return callback_error;
}

void
Client::fail_request(std::uint64_t stream_id, std::string const &error, qb::http::status status) {
    auto it = _active_requests.find(stream_id);
    if (it == _active_requests.end()) {
        return;
    }
    auto ctx = std::move(it->second);
    _active_requests.erase(it);
    ++_failed_requests;
    ctx->callback(create_error_response(status, error));
}

void
Client::fail_pending_request(std::uint64_t request_id, std::string const &error, qb::http::status status) {
    auto it = std::find_if(_pending_requests.begin(), _pending_requests.end(),
                           [request_id](auto const &ctx) { return ctx && ctx->request_id == request_id; });
    if (it == _pending_requests.end()) {
        return;
    }
    auto ctx = std::move(*it);
    _pending_requests.erase(it);
    ++_failed_requests;
    ctx->callback(create_error_response(status, error));
}

bool
Client::has_pending_or_active_work() const noexcept {
    return !_pending_requests.empty() || !_active_requests.empty() || !_active_batches.empty();
}

void
Client::arm_connect_timeout() {
    if (_connect_timeout <= qb::duration::zero()) {
        return;
    }
    auto       weak_self = weak_from_this();
    const auto epoch     = _connect_epoch;
    qb::io::async::callback(
        [weak_self, epoch]() {
            auto self = weak_self.lock();
            if (!self || self->_connect_epoch != epoch || !self->_is_connecting || self->is_connected()) {
                return;
            }
            self->close_failed_transport("HTTP/3 connection timeout");
            self->handle_connection_failure("HTTP/3 connection timeout");
        },
        _connect_timeout);
}

void
Client::arm_request_timeout(std::uint64_t request_id) {
    if (_request_timeout <= qb::duration::zero()) {
        return;
    }
    schedule_request_timeout(request_id, _request_timeout);
}

void
Client::schedule_request_timeout(std::uint64_t request_id, qb::duration delay) {
    auto weak_self = weak_from_this();
    qb::io::async::callback(
        [weak_self, request_id]() {
            auto self = weak_self.lock();
            if (!self) {
                return;
            }
            const auto now = std::chrono::steady_clock::now();
            for (auto const &ctx : self->_pending_requests) {
                if (!ctx || ctx->request_id != request_id) {
                    continue;
                }
                const auto elapsed = std::chrono::duration_cast<qb::duration>(now - ctx->created_at);
                if (elapsed >= self->_request_timeout) {
                    self->fail_pending_request(request_id, "HTTP/3 request timeout while pending", qb::http::status::REQUEST_TIMEOUT);
                    self->process_pending_requests();
                } else {
                    // The event-loop timer source can wake this callback slightly
                    // before the steady_clock deadline (the two clocks are not the
                    // same). Re-arm for the remaining time instead of dropping the
                    // timeout — otherwise the one-shot fire is lost and the request
                    // stays queued forever (never completes, never fails).
                    self->schedule_request_timeout(request_id, self->_request_timeout - elapsed);
                }
                return;
            }
            auto it = std::find_if(self->_active_requests.begin(), self->_active_requests.end(),
                                   [request_id](auto const &entry) { return entry.second && entry.second->request_id == request_id; });
            if (it == self->_active_requests.end()) {
                return;
            }
            const auto elapsed = std::chrono::duration_cast<qb::duration>(now - it->second->created_at);
            if (elapsed < self->_request_timeout) {
                // Woke early (see note above) — re-arm for the remaining time.
                self->schedule_request_timeout(request_id, self->_request_timeout - elapsed);
                return;
            }
            const auto stream_id = it->first;
            self->fail_request(stream_id, "HTTP/3 request timeout", qb::http::status::REQUEST_TIMEOUT);
            // Timeout aborts the in-flight request stream (RFC 9114 §4.1).
            self->reset_stream(0, stream_id, NGHTTP3_H3_REQUEST_CANCELLED);
            self->process_pending_requests();
        },
        delay);
}

qb::http::Response
Client::create_error_response(qb::http::status status, std::string const &message) {
    qb::http::Response response;
    response.status() = status;
    response.body()   = message;
    response.set_header("content-type", "text/plain");
    response.set_header("content-length", std::to_string(message.size()));
    return response;
}

std::uint64_t
Client::open_http3_unidirectional_stream(std::uint64_t connection_id) {
    return open_unidirectional_stream(connection_id).id();
}

void
Client::send_http3_stream_data(std::uint64_t connection_id, std::uint64_t stream_id, std::string_view data, bool fin) {
    send_stream_data(connection_id, stream_id, data, fin);
}

void
Client::extend_http3_stream_credit(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t bytes) {
    extend_stream_credit(connection_id, stream_id, bytes);
}

void
Client::reset_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t app_error_code) {
    reset_stream(connection_id, stream_id, app_error_code);
}

void
Client::stop_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t app_error_code) {
    stop_stream(connection_id, stream_id, app_error_code);
}

void
Client::close_http3_connection(std::uint64_t, std::uint64_t app_error_code, std::string_view reason) {
    close(app_error_code, reason);
}

void
Client::on_http3_stream_acked(std::uint64_t, std::uint64_t) {}

void
Client::on_http3_stream_closed(std::uint64_t stream_id, std::uint64_t) {
    if (_active_requests.find(stream_id) != _active_requests.end()) {
        fail_request(stream_id, "HTTP/3 stream closed before response completion");
    }
}

void
Client::on_http3_shutdown(std::uint64_t, std::uint64_t) {
    _remote_shutdown = true;
    while (!_pending_requests.empty()) {
        auto ctx = std::move(_pending_requests.front());
        _pending_requests.pop_front();
        ++_failed_requests;
        ctx->callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "HTTP/3 server is shutting down"));
    }
}

void
Client::on_http3_response(std::uint64_t stream_id, qb::http::Response response) {
    auto it = _active_requests.find(stream_id);
    if (it == _active_requests.end()) {
        return;
    }
    auto ctx = std::move(it->second);
    _active_requests.erase(it);
    ++_successful_requests;
    ctx->callback(std::move(response));
    process_pending_requests();
}

void
Client::dispatch(qb::io::async::quic::event::connected const &ev) {
    EventLifetime lifetime{*this};
    if (ev.negotiated_alpn != "h3") {
        close_failed_transport("HTTP/3 ALPN negotiation failed");
        handle_connection_failure("HTTP/3 ALPN negotiation failed: " + ev.negotiated_alpn);
        return;
    }
    handle_connection_success(ev.negotiated_alpn);
}

void
Client::dispatch(qb::io::async::quic::event::connection_closed const &ev) {
    EventLifetime lifetime{*this};
    if (_closing_failed_attempt || (_deferred_close && _deferred_close->empty())) {
        return; // the explicit close already owns notification and teardown
    }
    std::string reason = ev.reason_phrase.empty() ? "HTTP/3 connection closed" : ev.reason_phrase;
    if (ev.error_code != 0) {
        reason += " (" + std::to_string(ev.error_code) + ")";
    }
    // If a read is on the stack, this close was delivered reentrantly from a send inside
    // nghttp3_conn_read_stream2. Tearing _h3 down now would call nghttp3_conn_del mid-read
    // (UAF) and reconnect on a live-but-doomed stack. Defer: dispatch(stream_data) runs the
    // teardown + reconnect once the outermost read unwinds. First reason wins.
    if (_read_depth > 0 || _submit_depth > 0) {
        if (!_deferred_close) {
            _deferred_close = std::move(reason);
        }
        return;
    }
    // endpoint has marked its state closed, but its socket and watchers are
    // still attached. Retire them before failure callbacks may start a retry.
    close_failed_transport("HTTP/3 connection closed");
    handle_connection_failure(reason);
    if (_auto_reconnect && has_pending_or_active_work()) {
        connect(nullptr);
    }
}

void
Client::dispatch(qb::io::async::quic::event::stream_data const &ev) {
    if (!_h3) {
        return;
    }
    EventLifetime lifetime{*this};
    // Guard the read: a response callback reached from nghttp3_conn_read_stream2 can
    // reentrantly fail the connection (see _read_depth in client.h). While the read is on
    // the stack the teardown is deferred; run it here, after the outermost read unwinds and
    // the stack (including nghttp3's own frames) is clear. The RAII guard restores _read_depth
    // on EVERY exit — including an exception escaping read_stream — so a throw can never wedge
    // the counter ≥1 and permanently freeze the deferral / reconnect.
    struct DepthGuard {
        int &d;
        explicit DepthGuard(int &d_) noexcept
            : d(d_) {
            ++d;
        }
        ~DepthGuard() {
            --d;
        }
    };
    {
        DepthGuard guard(_read_depth);
        _h3->read_stream(ev.id, ev.payload, ev.fin);
    }
    if (_read_depth == 0 && _submit_depth == 0 && _deferred_close) {
        const std::string reason = std::move(*_deferred_close);
        _deferred_close.reset();
        if (reason.empty()) {
            disconnect(); // explicit intent: fail once and close after nghttp3 unwinds
            return;
        }
        close_failed_transport("HTTP/3 connection closed");
        handle_connection_failure(reason);
        if (_auto_reconnect && has_pending_or_active_work()) {
            connect(nullptr);
        }
    }
}

void
Client::dispatch(qb::io::async::quic::event::stream_data_acked const &ev) {
    if (_h3) {
        EventLifetime lifetime{*this};
        _h3->add_ack_offset(ev.id, ev.bytes);
    }
}

void
Client::dispatch(qb::io::async::quic::event::stream_closed const &ev) {
    EventLifetime lifetime{*this};
    on_http3_stream_closed(ev.id, ev.error_code);
    // nghttp3 frees a stream only when told, and the request, the response and the body copy kept
    // beside it go with it: until 3.2 nobody told it, and a long-lived connection kept every
    // exchange it had ever made. The engine reports the close back through
    // on_http3_stream_closed(), which by then finds the request already settled.
    if (_h3) {
        _h3->close_stream(ev.id, ev.error_code);
    }
}

qb::http::async::awaiter<ConnectResult>
Client::connect() {
    auto weak_self = weak_from_this();
    return qb::http::async::make_awaiter<ConnectResult>([weak_self](std::function<void(ConnectResult &&)> complete) mutable {
        auto self = weak_self.lock();
        if (!self) {
            complete(ConnectResult{false, "HTTP/3 client no longer available"});
            return;
        }
        auto completed       = std::make_shared<bool>(false);
        auto complete_holder = std::make_shared<std::function<void(ConnectResult &&)>>(std::move(complete));
        auto callback        = [completed, complete_holder](bool ok, std::string const &error) mutable {
            if (*completed) {
                return;
            }
            *completed = true;
            (*complete_holder)(ConnectResult{ok, error});
        };
        if (!self->connect(std::move(callback))) {
            if (!*completed) {
                *completed = true;
                (*complete_holder)(ConnectResult{self->is_connected(), self->is_connected() ? "" : "Unable to start connection"});
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
                qb::http::Response response;
                response.status() = qb::http::status::SERVICE_UNAVAILABLE;
                response.body()   = "HTTP/3 client no longer available";
                complete(std::move(response));
                return;
            }
            auto complete_holder = std::make_shared<std::function<void(qb::http::Response &&)>>(std::move(complete));
            if (!self->push_request(std::move(req),
                                    [complete_holder](qb::http::Response response) mutable { (*complete_holder)(std::move(response)); })) {
                qb::http::Response response;
                response.status() = qb::http::status::SERVICE_UNAVAILABLE;
                response.body()   = "Unable to queue HTTP/3 request";
                (*complete_holder)(std::move(response));
            }
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

std::shared_ptr<Client>
make_client(std::string const &base_uri) {
    return std::make_shared<Client>(base_uri);
}

std::shared_ptr<Client>
make_client(qb::io::uri const &uri) {
    return std::make_shared<Client>(uri);
}

} // namespace qb::http3

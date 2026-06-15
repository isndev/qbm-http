#include "client.h"

#include <algorithm>

#include "../origin.h"

namespace qb::http3 {

Client::Client(std::string const& base_uri)
    : _client_id(qb::generate_random_uuid()) {
    initialize_from_uri(qb::io::uri(base_uri));
}

Client::Client(qb::io::uri const& uri)
    : _client_id(qb::generate_random_uuid()) {
    initialize_from_uri(uri);
}

Client::~Client() {
    fail_all_requests("HTTP/3 client destroyed");
    disconnect();
}

void Client::initialize_from_uri(qb::io::uri const& uri) {
    if (!qb::http::origin::scheme_eq(uri.scheme(), "https")) {
        throw std::invalid_argument("HTTP/3 client only supports https scheme");
    }
    _base_uri = uri;
    _host = std::string(uri.host());
}

bool Client::connect(ConnectionCallback callback) {
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
    _is_connecting = true;
    _h3_ready = false;
    _remote_shutdown = false;

    qb::io::quic::tls_config tls;
    tls.server_name = _host;
    tls.verify_peer = _verify_peer;
    if (!qb::io::async::quic::endpoint::connect(_base_uri, std::move(tls), {"h3"})) {
        handle_connection_failure("Unable to start QUIC connection");
        return false;
    }
    arm_connect_timeout();
    return true;
}

void Client::disconnect() {
    fail_all_requests("HTTP/3 client disconnect");
    _is_connected = false;
    _is_connecting = false;
    _h3_ready = false;
    _remote_shutdown = false;
    _h3.reset();
    qb::io::async::quic::endpoint::close(0, "HTTP/3 client disconnect");
}

void Client::ensure_absolute_uri(qb::http::Request& request) {
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

std::optional<qb::http::Response> Client::prepare_request(qb::http::Request& request) {
    ensure_absolute_uri(request);
    if (request.uri().host().empty()) {
        return create_error_response(qb::http::status::BAD_REQUEST,
                                     "HTTP/3 request URI is missing a host");
    }
    if (!qb::http::origin::scheme_eq(request.uri().scheme(), "https")) {
        return create_error_response(qb::http::status::BAD_REQUEST,
                                     "HTTP/3 request URI must use https");
    }
    if (!qb::http::origin::same(request.uri(), _base_uri)) {
        return create_error_response(qb::http::status::BAD_REQUEST,
                                     "HTTP/3 persistent client only accepts same-origin requests");
    }
    return std::nullopt;
}

bool Client::push_request(qb::http::Request request, ResponseCallback callback) {
    if (!callback) {
        return false;
    }
    (void)push_request_with_id(std::move(request), std::move(callback));
    return true;
}

request_id Client::push_request_with_id(qb::http::Request request, ResponseCallback callback) {
    if (!callback) {
        return 0;
    }
    ++_total_requests;
    if (auto error = prepare_request(request)) {
        ++_failed_requests;
        callback(std::move(*error));
        return 0;
    }
    if (_remote_shutdown && is_connected()) {
        ++_failed_requests;
        callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE,
                                       "HTTP/3 server is shutting down"));
        return 0;
    }
    if (_pending_requests.size() + _active_requests.size() >= _max_pending_requests) {
        ++_failed_requests;
        callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE,
                                       "HTTP/3 client pending request limit reached"));
        return 0;
    }
    auto ctx = std::make_unique<RequestContext>();
    ctx->request = std::move(request);
    ctx->callback = std::move(callback);
    ctx->created_at = std::chrono::steady_clock::now();
    ctx->request_id = _next_request_id++;
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

bool Client::cancel_request(request_id id, std::string const& reason) {
    auto pending = std::find_if(_pending_requests.begin(), _pending_requests.end(),
                                [id](auto const& ctx) {
        return ctx && ctx->request_id == id;
    });
    if (pending != _pending_requests.end()) {
        auto ctx = std::move(*pending);
        _pending_requests.erase(pending);
        ++_failed_requests;
        ctx->callback(create_error_response(qb::http::status::CLIENT_CLOSED_REQUEST, reason));
        return true;
    }

    auto active = std::find_if(_active_requests.begin(), _active_requests.end(),
                               [id](auto const& entry) {
        return entry.second && entry.second->request_id == id;
    });
    if (active == _active_requests.end()) {
        return false;
    }
    const auto stream_id = active->first;
    fail_request(stream_id, reason, qb::http::status::CLIENT_CLOSED_REQUEST);
    reset_stream(0, stream_id, 0x0105);
    process_pending_requests();
    return true;
}

bool Client::push_requests(std::vector<qb::http::Request> requests, BatchResponseCallback callback) {
    if (requests.empty()) {
        if (callback) {
            callback({});
        }
        return true;
    }
    if (!callback) {
        return false;
    }
    if (_remote_shutdown && is_connected()) {
        std::vector<qb::http::Response> responses;
        responses.reserve(requests.size());
        for (std::size_t i = 0; i < requests.size(); ++i) {
            responses.push_back(create_error_response(qb::http::status::SERVICE_UNAVAILABLE,
                                                      "HTTP/3 server is shutting down"));
        }
        _total_requests += requests.size();
        _failed_requests += requests.size();
        callback(std::move(responses));
        return true;
    }

    const auto batch_id = _next_batch_id++;
    auto batch = std::make_unique<BatchRequestContext>();
    batch->callback = std::move(callback);
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
        auto ctx = std::make_unique<RequestContext>();
        ctx->request = std::move(requests[i]);
        ctx->created_at = std::chrono::steady_clock::now();
        ctx->request_id = _next_request_id++;
        ctx->batch_id = batch_id;
        const auto request_id = ctx->request_id;
        ctx->callback = [this, batch_id, i](qb::http::Response response) {
            auto it = _active_batches.find(batch_id);
            if (it == _active_batches.end()) {
                return;
            }
            auto& batch_ctx = *it->second;
            batch_ctx.responses[i] = std::move(response);
            batch_ctx.completed[i] = true;
            if (++batch_ctx.completed_count == batch_ctx.responses.size()) {
                auto done = std::move(batch_ctx.callback);
                auto responses = std::move(batch_ctx.responses);
                _active_batches.erase(it);
                done(std::move(responses));
            }
        };
        _pending_requests.push_back(std::move(ctx));
        arm_request_timeout(request_id);
    }

    if (batch->completed_count == batch->responses.size()) {
        callback(std::move(batch->responses));
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

void Client::process_pending_requests() {
    if (!_h3 || !is_connected() || _remote_shutdown) {
        return;
    }
    while (!_pending_requests.empty() && _active_requests.size() < _max_concurrent_streams) {
        auto ctx = std::move(_pending_requests.front());
        _pending_requests.pop_front();

        auto stream = open_bidirectional_stream(0);
        ctx->stream_id = stream.id();
        const auto stream_id = ctx->stream_id;
        if (!_h3->submit_request(stream_id, ctx->request)) {
            reset_stream(0, stream_id, 0x0105);
            ++_failed_requests;
            ctx->callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE,
                                                "Failed to submit HTTP/3 request"));
            continue;
        }
        _active_requests.emplace(stream_id, std::move(ctx));
    }
}

void Client::handle_connection_success(std::string const& alpn) {
    _is_connected = true;
    _is_connecting = false;
    _h3_ready = true;
    _remote_shutdown = false;
    _h3 = std::make_unique<h3_connection>(*this, 0, h3_connection::role::client);
    _h3->bind_local_streams();
    auto callbacks = std::move(_connection_callbacks);
    _connection_callbacks.clear();
    for (auto& cb : callbacks) {
        if (cb) {
            cb(true, {});
        }
    }
    process_pending_requests();
    LOG_HTTP_INFO_PA(_client_id, "HTTP/3 connected with ALPN " << alpn);
}

void Client::handle_connection_failure(std::string const& error) {
    _is_connected = false;
    _is_connecting = false;
    _h3_ready = false;
    _remote_shutdown = false;
    _h3.reset();
    auto callbacks = std::move(_connection_callbacks);
    _connection_callbacks.clear();
    for (auto& cb : callbacks) {
        if (cb) {
            cb(false, error);
        }
    }
    fail_all_requests(error);
}

void Client::fail_all_requests(std::string const& error) {
    qb::unordered_map<std::uint64_t, std::unique_ptr<RequestContext>> active;
    std::deque<std::unique_ptr<RequestContext>> pending;
    qb::unordered_map<std::uint64_t, std::unique_ptr<BatchRequestContext>> batches;
    active.swap(_active_requests);
    pending.swap(_pending_requests);
    batches.swap(_active_batches);

    for (auto& [id, ctx] : active) {
        (void)id;
        if (ctx->batch_id != 0) {
            continue;
        }
        ++_failed_requests;
        ctx->callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, error));
    }
    while (!pending.empty()) {
        auto ctx = std::move(pending.front());
        pending.pop_front();
        if (ctx->batch_id != 0) {
            continue;
        }
        ++_failed_requests;
        ctx->callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, error));
    }
    for (auto& [id, batch] : batches) {
        (void)id;
        for (std::size_t i = 0; i < batch->responses.size(); ++i) {
            if (i >= batch->completed.size() || !batch->completed[i]) {
                ++_failed_requests;
                batch->responses[i] =
                    create_error_response(qb::http::status::SERVICE_UNAVAILABLE, error);
            }
        }
        batch->callback(std::move(batch->responses));
    }
}

void Client::fail_request(std::uint64_t stream_id, std::string const& error,
                          qb::http::status status) {
    auto it = _active_requests.find(stream_id);
    if (it == _active_requests.end()) {
        return;
    }
    auto ctx = std::move(it->second);
    _active_requests.erase(it);
    ++_failed_requests;
    ctx->callback(create_error_response(status, error));
}

void Client::fail_pending_request(std::uint64_t request_id, std::string const& error,
                                  qb::http::status status) {
    auto it = std::find_if(_pending_requests.begin(), _pending_requests.end(),
                           [request_id](auto const& ctx) {
        return ctx && ctx->request_id == request_id;
    });
    if (it == _pending_requests.end()) {
        return;
    }
    auto ctx = std::move(*it);
    _pending_requests.erase(it);
    ++_failed_requests;
    ctx->callback(create_error_response(status, error));
}

bool Client::has_pending_or_active_work() const noexcept {
    return !_pending_requests.empty() || !_active_requests.empty() || !_active_batches.empty();
}

void Client::arm_connect_timeout() {
    if (_connect_timeout <= qb::duration::zero()) {
        return;
    }
    auto weak_self = weak_from_this();
    qb::io::async::callback([weak_self]() {
        auto self = weak_self.lock();
        if (!self || !self->_is_connecting || self->is_connected()) {
            return;
        }
        self->handle_connection_failure("HTTP/3 connection timeout");
        static_cast<qb::io::async::quic::endpoint&>(*self)
            .close(0, "HTTP/3 connection timeout");
    }, _connect_timeout);
}

void Client::arm_request_timeout(std::uint64_t request_id) {
    if (_request_timeout <= qb::duration::zero()) {
        return;
    }
    auto weak_self = weak_from_this();
    qb::io::async::callback([weak_self, request_id]() {
        auto self = weak_self.lock();
        if (!self) {
            return;
        }
        for (auto const& ctx : self->_pending_requests) {
            if (!ctx || ctx->request_id != request_id) {
                continue;
            }
            auto const elapsed = std::chrono::duration_cast<qb::duration>(
                std::chrono::steady_clock::now() - ctx->created_at);
            if (elapsed >= self->_request_timeout) {
                self->fail_pending_request(request_id, "HTTP/3 request timeout while pending",
                                           qb::http::status::REQUEST_TIMEOUT);
                self->process_pending_requests();
            }
            return;
        }
        auto it = std::find_if(self->_active_requests.begin(), self->_active_requests.end(),
                               [request_id](auto const& entry) {
            return entry.second && entry.second->request_id == request_id;
        });
        if (it == self->_active_requests.end()) {
            return;
        }
        auto const elapsed = std::chrono::duration_cast<qb::duration>(
            std::chrono::steady_clock::now() - it->second->created_at);
        if (elapsed < self->_request_timeout) {
            return;
        }
        const auto stream_id = it->first;
        self->fail_request(stream_id, "HTTP/3 request timeout",
                           qb::http::status::REQUEST_TIMEOUT);
        self->reset_stream(0, stream_id, 0x0105);
        self->process_pending_requests();
    }, _request_timeout);
}

qb::http::Response Client::create_error_response(qb::http::status status,
                                                 std::string const& message) {
    qb::http::Response response;
    response.status() = status;
    response.body() = message;
    response.set_header("content-type", "text/plain");
    response.set_header("content-length", std::to_string(message.size()));
    return response;
}

std::uint64_t Client::open_http3_unidirectional_stream(std::uint64_t connection_id) {
    return open_unidirectional_stream(connection_id).id();
}

void Client::send_http3_stream_data(std::uint64_t connection_id, std::uint64_t stream_id,
                                    std::string_view data, bool fin) {
    send_stream_data(connection_id, stream_id, data, fin);
}

void Client::extend_http3_stream_credit(std::uint64_t connection_id, std::uint64_t stream_id,
                                        std::uint64_t bytes) {
    extend_stream_credit(connection_id, stream_id, bytes);
}

void Client::reset_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id,
                                std::uint64_t app_error_code) {
    reset_stream(connection_id, stream_id, app_error_code);
}

void Client::stop_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id,
                               std::uint64_t app_error_code) {
    stop_stream(connection_id, stream_id, app_error_code);
}

void Client::close_http3_connection(std::uint64_t, std::uint64_t app_error_code,
                                    std::string_view reason) {
    close(app_error_code, reason);
}

void Client::on_http3_stream_acked(std::uint64_t, std::uint64_t) {}

void Client::on_http3_stream_closed(std::uint64_t stream_id, std::uint64_t) {
    if (_active_requests.find(stream_id) != _active_requests.end()) {
        fail_request(stream_id, "HTTP/3 stream closed before response completion");
    }
}

void Client::on_http3_shutdown(std::uint64_t, std::uint64_t) {
    _remote_shutdown = true;
    while (!_pending_requests.empty()) {
        auto ctx = std::move(_pending_requests.front());
        _pending_requests.pop_front();
        ++_failed_requests;
        ctx->callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE,
                                            "HTTP/3 server is shutting down"));
    }
}

void Client::on_http3_response(std::uint64_t stream_id, qb::http::Response response) {
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

void Client::dispatch(qb::io::async::quic::event::connected const& ev) {
    if (ev.negotiated_alpn != "h3") {
        handle_connection_failure("HTTP/3 ALPN negotiation failed: " + ev.negotiated_alpn);
        return;
    }
    handle_connection_success(ev.negotiated_alpn);
}

void Client::dispatch(qb::io::async::quic::event::connection_closed const& ev) {
    std::string reason = ev.reason_phrase.empty() ? "HTTP/3 connection closed" : ev.reason_phrase;
    if (ev.error_code != 0) {
        reason += " (" + std::to_string(ev.error_code) + ")";
    }
    handle_connection_failure(reason);
    if (_auto_reconnect && has_pending_or_active_work()) {
        connect(nullptr);
    }
}

void Client::dispatch(qb::io::async::quic::event::stream_data const& ev) {
    if (_h3) {
        _h3->read_stream(ev.id, ev.payload, ev.fin);
    }
}

void Client::dispatch(qb::io::async::quic::event::stream_data_acked const& ev) {
    if (_h3) {
        _h3->add_ack_offset(ev.id, ev.bytes);
    }
}

void Client::dispatch(qb::io::async::quic::event::stream_closed const& ev) {
    on_http3_stream_closed(ev.id, ev.error_code);
}

qb::http::async::awaiter<ConnectResult> Client::connect() {
    auto weak_self = weak_from_this();
    return qb::http::async::make_awaiter<ConnectResult>(
        [weak_self](std::function<void(ConnectResult&&)> complete) mutable {
            auto self = weak_self.lock();
            if (!self) {
                complete(ConnectResult{false, "HTTP/3 client no longer available"});
                return;
            }
            auto completed = std::make_shared<bool>(false);
            auto complete_holder =
                std::make_shared<std::function<void(ConnectResult&&)>>(std::move(complete));
            auto callback = [completed, complete_holder]
                            (bool ok, std::string const& error) mutable {
                if (*completed) {
                    return;
                }
                *completed = true;
                (*complete_holder)(ConnectResult{ok, error});
            };
            if (!self->connect(std::move(callback))) {
                if (!*completed) {
                    *completed = true;
                    (*complete_holder)(ConnectResult{
                        self->is_connected(),
                        self->is_connected() ? "" : "Unable to start connection"});
                }
            }
        });
}

qb::http::async::awaiter<qb::http::Response>
Client::push_request(qb::http::Request request) {
    auto weak_self = weak_from_this();
    return qb::http::async::make_awaiter<qb::http::Response>(
        [weak_self, req = std::move(request)](std::function<void(qb::http::Response&&)> complete) mutable {
            auto self = weak_self.lock();
            if (!self) {
                qb::http::Response response;
                response.status() = qb::http::status::SERVICE_UNAVAILABLE;
                response.body() = "HTTP/3 client no longer available";
                complete(std::move(response));
                return;
            }
            auto complete_holder =
                std::make_shared<std::function<void(qb::http::Response&&)>>(std::move(complete));
            if (!self->push_request(std::move(req),
                    [complete_holder](qb::http::Response response) mutable {
                        (*complete_holder)(std::move(response));
                    })) {
                qb::http::Response response;
                response.status() = qb::http::status::SERVICE_UNAVAILABLE;
                response.body() = "Unable to queue HTTP/3 request";
                (*complete_holder)(std::move(response));
            }
        });
}

qb::http::async::awaiter<std::vector<qb::http::Response>>
Client::push_requests(std::vector<qb::http::Request> requests) {
    auto weak_self = weak_from_this();
    return qb::http::async::make_awaiter<std::vector<qb::http::Response>>(
        [weak_self, reqs = std::move(requests)]
        (std::function<void(std::vector<qb::http::Response>&&)> complete) mutable {
            auto self = weak_self.lock();
            if (!self) {
                complete({});
                return;
            }
            self->push_requests(std::move(reqs),
                [complete = std::move(complete)](std::vector<qb::http::Response> responses) mutable {
                    complete(std::move(responses));
                });
        });
}

std::shared_ptr<Client> make_client(std::string const& base_uri) {
    return std::make_shared<Client>(base_uri);
}

std::shared_ptr<Client> make_client(qb::io::uri const& uri) {
    return std::make_shared<Client>(uri);
}

} // namespace qb::http3

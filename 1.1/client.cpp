#include "./client.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

#include <qb/io/async/tcp/connector.h>
#include <qb/io/transport/tcp.h>
#ifdef QB_HAS_SSL
#include <qb/io/transport/stcp.h>
#endif

#include "./http.h"
#include "../headers.h"
#include "../origin.h"
#include "../utility.h"

namespace qb::http1 {
namespace {

[[nodiscard]] bool has_connection_close(qb::http::Response const& response) {
    auto it = response.headers().find("Connection");
    if (it == response.headers().end()) {
        return false;
    }
    for (auto const& value : it->second) {
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
    Client& _owner;
    qb::http::method _active_method = qb::http::method::GET;
    std::shared_ptr<bool> _alive = std::make_shared<bool>(true);

public:
    using http_protocol = qb::protocol::http::client<connection<Transport>>;

    explicit connection(Client& owner)
        : _owner(owner) {
        this->template switch_protocol<http_protocol>(*this);
        this->setTimeout(0);
    }

    ~connection() override {
        *_alive = false;
    }

    [[nodiscard]] bool http1_response_body_forbidden() const noexcept {
        return _active_method == qb::http::Method::HEAD;
    }

    void connect(qb::io::uri const& uri, double timeout, bool verify_peer) override {
        auto alive = std::weak_ptr<bool>(_alive);
        qb::io::async::tcp::connect<typename Transport::transport_io_type>(
            uri,
            [this, alive, timeout](auto&& socket) {
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
            timeout,
            verify_peer);
    }

    void disconnect() override {
        this->base_t::disconnect(1);
    }

    void send(qb::http::Request request, double timeout) override {
        _active_method = request.method();
#ifdef QB_HAS_COMPRESSION
        try {
            if (request.has_header("Content-Encoding")) {
                request.body().compress(request.header("Content-Encoding"));
            }
        } catch (std::exception const& e) {
            _owner.fail_active_request(e.what(), qb::http::status::BAD_REQUEST);
            return;
        }
#else
        request.remove_header("Content-Encoding");
#endif
        try {
            *this << request;
            this->setTimeout(timeout);
        } catch (std::exception const& e) {
            _owner.fail_active_request(e.what(), qb::http::status::BAD_REQUEST);
        }
    }

    [[nodiscard]] bool is_open() const noexcept override {
        return this->transport().is_open();
    }

    void on(typename http_protocol::response response) {
        auto owner_guard = _owner.weak_from_this().lock();
        this->setTimeout(0);
#ifdef QB_HAS_COMPRESSION
        try {
            if (response.has_header("Content-Encoding")) {
                response.body().uncompress(response.header("Content-Encoding"));
            }
        } catch (std::exception const& e) {
            response.status() = qb::http::status::BAD_REQUEST;
            response.body() = std::string(e.what());
        }
#endif
        _owner.handle_response(std::move(response));
    }

    void on(qb::io::async::event::timeout const&) {
        auto owner_guard = _owner.weak_from_this().lock();
        _owner.handle_timeout();
    }

    void on(qb::io::async::event::disconnected const& event) {
        auto owner_guard = _owner.weak_from_this().lock();
        _owner.handle_disconnected(event.reason);
    }

    void on(qb::io::async::event::dispose const&) {}
};

class Client::callback_scope {
    Client& _client;

public:
    explicit callback_scope(Client& client)
        : _client(client) {
        _client.enter_user_callback();
    }

    ~callback_scope() {
        _client.leave_user_callback();
    }
};

Client::Client(std::string const& base_uri)
    : Client(qb::io::uri(base_uri)) {}

Client::Client(qb::io::uri const& uri) {
    initialize_from_uri(uri);
}

Client::~Client() {
    disconnect();
}

void Client::initialize_from_uri(qb::io::uri const& uri) {
#ifdef QB_HAS_SSL
    if (!qb::http::origin::scheme_eq(uri.scheme(), "http") &&
        !qb::http::origin::scheme_eq(uri.scheme(), "https")) {
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
    _host = qb::http::host_header_value(_base_uri);
    create_connection();
}

void Client::create_connection() {
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

bool Client::connect(ConnectionCallback callback) {
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
    _is_connecting = true;
    if (!_connection || !_connection->is_open()) {
        create_connection();
    }
    _connection->connect(_base_uri, _connect_timeout, _verify_peer);
    return true;
}

qb::http::async::awaiter<ConnectResult> Client::connect() {
    auto weak_self = weak_from_this();
    return qb::http::async::make_awaiter<ConnectResult>(
        [weak_self](std::function<void(ConnectResult&&)> complete) mutable {
            auto self = weak_self.lock();
            if (!self) {
                complete(ConnectResult{false, "HTTP/1.1 client no longer available"});
                return;
            }
            if (!self->connect([complete = std::move(complete)](bool ok, std::string const& err) mutable {
                    complete(ConnectResult{ok, err});
                })) {
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

void Client::disconnect() {
    _intentional_disconnect = true;
    _is_connected = false;
    _is_connecting = false;
    _reconnect_after_disconnect = false;
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

void Client::ensure_absolute_uri(qb::http::Request& request) {
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

std::optional<qb::http::Response> Client::prepare_request(qb::http::Request& request) {
    ensure_absolute_uri(request);
    if (request.uri().host().empty()) {
        return create_error_response(qb::http::status::BAD_REQUEST,
                                     "HTTP/1.1 request URI is missing a host");
    }
    if (!qb::http::origin::same(request.uri(), _base_uri)) {
        return create_error_response(qb::http::status::BAD_REQUEST,
                                     "HTTP/1.1 persistent client only accepts same-origin requests");
    }
    if (!request.has_header("Host")) {
        request.set_header("Host", _host);
    }
    if (!request.has_header("User-Agent")) {
        request.set_header("User-Agent", "qb/1.0.0");
    }
    if (!request.has_header("Accept-Encoding")) {
        request.set_header("Accept-Encoding", qb::http::accept_encoding());
    }
    return std::nullopt;
}

bool Client::push_request(qb::http::Request request, ResponseCallback callback) {
    if (!callback) {
        return false;
    }
    ++_total_requests;
    if (auto error = prepare_request(request)) {
        ++_failed_requests;
        callback_scope scope(*this);
        callback(std::move(*error));
        return true;
    }
    if (_pending_requests.size() + (_active_request ? 1u : 0u) >= _max_pending_requests) {
        ++_failed_requests;
        callback_scope scope(*this);
        callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE,
                                       "HTTP/1.1 client pending request limit reached"));
        return false;
    }
    auto ctx = std::make_unique<RequestContext>();
    ctx->request_id = _next_request_id++;
    ctx->request = std::move(request);
    ctx->callback = std::move(callback);
    ctx->created_at = std::chrono::steady_clock::now();
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
        [weak_self, req = std::move(request)](std::function<void(qb::http::Response&&)> complete) mutable {
            auto self = weak_self.lock();
            if (!self) {
                qb::http::Response response;
                response.status() = qb::http::status::SERVICE_UNAVAILABLE;
                response.body() = "HTTP/1.1 client no longer available";
                complete(std::move(response));
                return;
            }
            self->push_request(std::move(req),
                [complete = std::move(complete)](qb::http::Response response) mutable {
                    complete(std::move(response));
                });
        });
}

bool Client::push_requests(std::vector<qb::http::Request> requests, BatchResponseCallback callback) {
    if (!callback) {
        return false;
    }
    if (requests.empty()) {
        callback_scope scope(*this);
        callback({});
        return true;
    }
    const auto batch_id = _next_batch_id++;
    auto batch = std::make_unique<BatchRequestContext>();
    batch->callback = std::move(callback);
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
                auto& batch_ref = *it->second;
                batch_ref.responses[index] = std::move(response);
                if (++batch_ref.completed_count == batch_ref.responses.size()) {
                    auto done = std::move(batch_ref.responses);
                    auto cb = std::move(batch_ref.callback);
                    _active_batches.erase(it);
                    if (cb) {
                        callback_scope scope(*this);
                        cb(std::move(done));
                    }
                }
            }) && queued_all;
    }
    return queued_all;
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

void Client::process_pending_requests() {
    if (_active_request || _pending_requests.empty()) {
        return;
    }
    if (!_is_connected || !_connection || !_connection->is_open()) {
        if (!_auto_reconnect) {
            auto ctx = std::move(_pending_requests.front());
            _pending_requests.pop_front();
            ++_failed_requests;
            callback_scope scope(*this);
            ctx->callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE,
                                                "HTTP/1.1 client is not connected"));
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

void Client::hold_through_current_tick() {
    auto self = weak_from_this().lock();
    if (!self) {
        return;
    }
    _callback_self_guard = std::move(self);
    auto weak_self = weak_from_this();
    qb::io::async::callback([weak_self]() {
        if (auto self = weak_self.lock()) {
            self->reset_deferred_connection_if_ready();
            self->_callback_self_guard.reset();
        }
    }, 0.000001);
}

void Client::enter_user_callback() {
    ++_callback_depth;
    hold_through_current_tick();
}

void Client::leave_user_callback() noexcept {
    if (_callback_depth) {
        --_callback_depth;
    }
}

void Client::reset_deferred_connection_if_ready() {
    if (_callback_depth || !_deferred_connection_reset) {
        return;
    }
    _deferred_connection_reset = false;
    _connection.reset();
}

void Client::arm_pending_timeout(std::uint64_t request_id) {
    if (_request_timeout <= 0.) {
        return;
    }
    auto weak_self = weak_from_this();
    qb::io::async::callback([weak_self, request_id]() {
        auto self = weak_self.lock();
        if (!self) {
            return;
        }
        if (self->fail_pending_request(request_id,
                                       "HTTP/1.1 request timeout while pending",
                                       qb::http::status::REQUEST_TIMEOUT)) {
            self->process_pending_requests();
        }
    }, _request_timeout);
}

bool Client::fail_pending_request(std::uint64_t request_id,
                                  std::string const& error,
                                  qb::http::status status) {
    auto self_guard = weak_from_this().lock();
    for (auto it = _pending_requests.begin(); it != _pending_requests.end(); ++it) {
        if (!*it || (*it)->request_id != request_id) {
            continue;
        }
        auto ctx = std::move(*it);
        _pending_requests.erase(it);
        ++_failed_requests;
        callback_scope scope(*this);
        ctx->callback(create_error_response(status, error));
        return true;
    }
    return false;
}

void Client::handle_connection_success() {
    auto self_guard = weak_from_this().lock();
    _is_connected = true;
    _is_connecting = false;
    _intentional_disconnect = false;
    auto callbacks = std::move(_connection_callbacks);
    _connection_callbacks.clear();
    for (auto& cb : callbacks) {
        if (cb) {
            callback_scope scope(*this);
            cb(true, "");
        }
    }
    if (_intentional_disconnect) {
        return;
    }
    process_pending_requests();
}

void Client::handle_connection_failure(std::string const& error) {
    auto self_guard = weak_from_this().lock();
    _is_connected = false;
    _is_connecting = false;
    auto callbacks = std::move(_connection_callbacks);
    _connection_callbacks.clear();
    for (auto& cb : callbacks) {
        if (cb) {
            callback_scope scope(*this);
            cb(false, error);
        }
    }
    if (_active_request) {
        fail_active_request(error);
    }
    fail_all_requests(error);
}

void Client::handle_response(qb::http::Response response) {
    auto self_guard = weak_from_this().lock();
    if (!_active_request) {
        return;
    }
    auto ctx = std::move(_active_request);
    const bool keep_alive = response.keep_alive && !has_connection_close(response);
    ++_successful_requests;
    callback_scope scope(*this);
    ctx->callback(std::move(response));
    if (_intentional_disconnect) {
        return;
    }
    if (!keep_alive) {
        _is_connected = false;
        _reconnect_after_disconnect = has_pending_work();
        if (_connection) {
            _connection->disconnect();
        }
        if (_reconnect_after_disconnect && _auto_reconnect && !_is_connecting) {
            auto weak_self = weak_from_this();
            qb::io::async::callback([weak_self]() {
                auto self = weak_self.lock();
                if (!self || self->_is_connected || self->_is_connecting || !self->has_pending_work()) {
                    return;
                }
                self->create_connection();
                self->connect(nullptr);
            });
        }
        return;
    }
    process_pending_requests();
}

void Client::handle_timeout() {
    if (_is_connecting && !_is_connected) {
        handle_connection_failure("Connection timeout");
        return;
    }
    fail_active_request("Request timeout", qb::http::status::GATEWAY_TIMEOUT);
    if (_connection) {
        _connection->disconnect();
    }
}

void Client::handle_disconnected(int reason) {
    const bool intentional = _intentional_disconnect || reason != 0;
    _is_connected = false;
    _is_connecting = false;
    if (_active_request) {
        fail_active_request(intentional ? "Connection closed" : "Connection lost");
    }
    if (_intentional_disconnect) {
        return;
    }
    if (has_pending_work() && _auto_reconnect) {
        auto weak_self = weak_from_this();
        qb::io::async::callback([weak_self]() {
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

void Client::fail_active_request(std::string const& error, qb::http::status status) {
    auto self_guard = weak_from_this().lock();
    if (!_active_request) {
        return;
    }
    auto ctx = std::move(_active_request);
    ++_failed_requests;
    callback_scope scope(*this);
    ctx->callback(create_error_response(status, error));
}

void Client::fail_all_requests(std::string const& error, qb::http::status status) {
    auto self_guard = weak_from_this().lock();
    while (!_pending_requests.empty()) {
        auto ctx = std::move(_pending_requests.front());
        _pending_requests.pop_front();
        ++_failed_requests;
        callback_scope scope(*this);
        ctx->callback(create_error_response(status, error));
    }
}

bool Client::has_pending_work() const noexcept {
    return _active_request || !_pending_requests.empty();
}

qb::http::Response Client::create_error_response(qb::http::status status,
                                                 std::string const& message) {
    qb::http::Response response;
    response.status() = status;
    response.body() = message;
    response.set_header("content-type", "text/plain");
    response.set_header("content-length", std::to_string(response.body().raw().size()));
    response.keep_alive = false;
    return response;
}

std::shared_ptr<Client> make_client(std::string const& base_uri) {
    return std::make_shared<Client>(base_uri);
}

std::shared_ptr<Client> make_client(qb::io::uri const& uri) {
    return std::make_shared<Client>(uri);
}

} // namespace qb::http1

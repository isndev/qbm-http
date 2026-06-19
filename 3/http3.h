/**
 * @file qbm/http/3/http3.h
 * @brief Native HTTP/3 server integration for qbm/http.
 */
#pragma once

#ifndef QBM_HTTP_HAS_HTTP3
#error "HTTP/3 support is not enabled. Build qbm/http with QBM_HTTP_HAS_HTTP3."
#endif

#include <filesystem>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include <qb/io/async/quic/endpoint.h>
#include <qb/system/allocator/pipe.h>
#include <qb/system/container/unordered_map.h>
#include <qb/system/container/unordered_set.h>

#include "../1.1/http.h"
#include "../routing/router.h"
#include "protocol/connection.h"

namespace qb::http3 {

namespace internal {

struct stream_key {
    std::uint64_t connection_id = 0;
    std::uint64_t stream_id     = 0;

    friend bool operator==(stream_key const &, stream_key const &) = default;
};

struct stream_key_hash {
    std::size_t
    operator()(stream_key const &key) const noexcept {
        auto h1 = std::hash<std::uint64_t>{}(key.connection_id);
        auto h2 = std::hash<std::uint64_t>{}(key.stream_id);
        return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6U) + (h1 >> 2U));
    }
};

template <typename Derived, typename Handler>
class session : public std::enable_shared_from_this<Derived> {
public:
    using handler_type = Handler;
    using ContextType  = qb::http::Context<Derived>;
    using Router       = qb::http::Router<Derived>;

private:
    Handler                     *_server         = nullptr;
    std::uint64_t                _connection_id  = 0;
    std::uint64_t                _stream_id      = 0;
    qb::http::Method             _request_method = qb::http::Method::UNINITIALIZED;
    qb::allocator::pipe<char>    _out;
    std::shared_ptr<ContextType> _context;
    bool                         _response_sent = false;

public:
    session() = delete;

    explicit session(Handler &server)
        : _server(&server) {}

    [[nodiscard]] Handler &
    server() noexcept {
        return *_server;
    }
    [[nodiscard]] Handler const &
    server() const noexcept {
        return *_server;
    }
    [[nodiscard]] std::uint64_t
    connection_id() const noexcept {
        return _connection_id;
    }
    [[nodiscard]] std::uint64_t
    id() const noexcept {
        return _stream_id;
    }
    [[nodiscard]] qb::allocator::pipe<char> &
    out() noexcept {
        return _out;
    }
    [[nodiscard]] Router &
    router() noexcept {
        return _server->router();
    }

    void
    bind_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id) noexcept {
        _connection_id = connection_id;
        _stream_id     = stream_id;
    }

    void
    bind_http3_request_method(qb::http::Method method) noexcept {
        _request_method = method;
    }

    void
    attach_context(std::shared_ptr<ContextType> context) noexcept {
        _context = std::move(context);
        if (_response_sent && _context) {
            _context->execute_hook(qb::http::HookPoint::POST_RESPONSE_SEND);
            _context.reset();
        }
    }

    void
    cancel_context(std::string const &reason) noexcept {
        if (_context) {
            _context->cancel(reason);
            _context.reset();
        }
    }

    void
    mark_response_sent() {
        if (_response_sent) {
            return;
        }
        _response_sent = true;
        if (_context) {
            _context->execute_hook(qb::http::HookPoint::POST_RESPONSE_SEND);
            _context.reset();
        }
    }

    [[nodiscard]] bool
    has_active_context() const noexcept {
        return static_cast<bool>(_context);
    }

    auto &
    operator<<(qb::http::Response &response) {
        response.stream_id = _stream_id;
        if (_request_method == qb::http::method::HEAD) {
            auto head_response = response;
            if (!head_response.has_header("content-length") && !response.body().empty()) {
                head_response.set_header("content-length", std::to_string(response.body().size()));
            }
            head_response.body().clear();
            _server->send_response(_connection_id, _stream_id, head_response);
            return _out;
        }
        if (!response.has_header("content-length") && !response.body().empty()) {
            response.set_header("content-length", std::to_string(response.body().size()));
        }
        _server->send_response(_connection_id, _stream_id, response);
        return _out;
    }
};

template <typename Derived, typename SessionType>
class server : public qb::io::async::quic::endpoint {
public:
    using session_type  = SessionType;
    using ContextType   = qb::http::Context<SessionType>;
    using Router        = qb::http::Router<SessionType>;
    using h3_connection = qb::protocol::http3::connection<server<Derived, SessionType>>;

private:
    Router                                                                       _router;
    qb::unordered_map<std::uint64_t, std::unique_ptr<h3_connection>>             _connections;
    qb::unordered_map<stream_key, std::shared_ptr<SessionType>, stream_key_hash> _sessions;
    qb::unordered_set<std::uint64_t>                                             _shutdown_connections;
    std::vector<std::uint64_t>                                                   _closed_connections;
    std::size_t                                                                  _max_body_size = 64 * 1024 * 1024;

    [[nodiscard]] h3_connection *
    connection(std::uint64_t connection_id) noexcept {
        auto it = _connections.find(connection_id);
        return it == _connections.end() ? nullptr : it->second.get();
    }

    [[nodiscard]] h3_connection &
    ensure_connection(std::uint64_t connection_id) {
        auto it = _connections.find(connection_id);
        if (it != _connections.end()) {
            return *it->second;
        }
        auto  conn = std::make_unique<h3_connection>(*this, connection_id, h3_connection::role::server);
        auto &ref  = *conn;
        _connections.emplace(connection_id, std::move(conn));
        ref.bind_local_streams();
        return ref;
    }

    [[nodiscard]] bool
    has_sessions(std::uint64_t connection_id) const noexcept {
        for (auto const &[key, _] : _sessions) {
            if (key.connection_id == connection_id) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] bool
    has_active_contexts(std::uint64_t connection_id) const noexcept {
        for (auto const &[key, session] : _sessions) {
            if (key.connection_id == connection_id && session && session->has_active_context()) {
                return true;
            }
        }
        return false;
    }

    void
    maybe_finish_graceful_shutdown(std::uint64_t connection_id) {
        if (_shutdown_connections.find(connection_id) == _shutdown_connections.end()) {
            return;
        }
        if (has_active_contexts(connection_id)) {
            return;
        }
        close_http3_connection(connection_id, 0, "HTTP/3 graceful shutdown");
    }

    [[nodiscard]] std::shared_ptr<SessionType>
    ensure_session(std::uint64_t connection_id, std::uint64_t stream_id) {
        stream_key key{connection_id, stream_id};
        auto       it = _sessions.find(key);
        if (it != _sessions.end()) {
            return it->second;
        }
        auto session = std::make_shared<SessionType>(static_cast<Derived &>(*this));
        session->bind_http3_stream(connection_id, stream_id);
        _sessions.emplace(key, session);
        return session;
    }

protected:
    void
    dispatch(qb::io::async::quic::event::connected const &ev) override {
        if (ev.negotiated_alpn != "h3") {
            close_http3_connection(ev.connection_id, 0x010c, "HTTP/3 ALPN mismatch");
            return;
        }
        (void) ensure_connection(ev.connection_id);
        if constexpr (requires(Derived &derived, qb::io::async::quic::event::connected const &e) { derived.on(e); }) {
            static_cast<Derived &>(*this).on(ev);
        }
    }

    void
    dispatch(qb::io::async::quic::event::connection_closed const &ev) override {
        for (auto it = _sessions.begin(); it != _sessions.end();) {
            if (it->first.connection_id == ev.connection_id) {
                it->second->cancel_context("HTTP/3 connection closed");
                it = _sessions.erase(it);
            } else {
                ++it;
            }
        }
        if (connection(ev.connection_id)) {
            _closed_connections.push_back(ev.connection_id);
        }
        _shutdown_connections.erase(ev.connection_id);
        if constexpr (requires(Derived &derived, qb::io::async::quic::event::connection_closed const &e) { derived.on(e); }) {
            static_cast<Derived &>(*this).on(ev);
        }
    }

    void
    dispatch(qb::io::async::quic::event::stream_data const &ev) override {
        auto &conn = ensure_connection(ev.connection_id);
        conn.read_stream(ev.id, ev.payload, ev.fin);
    }

    void
    dispatch(qb::io::async::quic::event::stream_data_acked const &ev) override {
        if (auto *conn = connection(ev.connection_id)) {
            conn->add_ack_offset(ev.id, ev.bytes);
        }
    }

    void
    dispatch(qb::io::async::quic::event::stream_closed const &ev) override {
        stream_key key{ev.connection_id, ev.id};
        auto       it = _sessions.find(key);
        if (it != _sessions.end()) {
            it->second->cancel_context("HTTP/3 stream closed");
            _sessions.erase(it);
        }
    }

    void
    after_dispatch_events() override {
        for (auto connection_id : _closed_connections) {
            _connections.erase(connection_id);
        }
        _closed_connections.clear();
    }

public:
    server()  = default;
    ~server() = default;

    [[nodiscard]] Router &
    router() noexcept {
        return _router;
    }
    [[nodiscard]] Router const &
    router() const noexcept {
        return _router;
    }

    void
    set_max_body_size(std::size_t value) noexcept {
        _max_body_size = value;
    }
    [[nodiscard]] std::size_t
    max_http3_body_size() const noexcept {
        return _max_body_size;
    }

    bool
    listen(qb::io::uri const &uri, std::filesystem::path const &cert_file, std::filesystem::path const &key_file) {
        return qb::io::async::quic::endpoint::listen(uri, cert_file, key_file, {"h3"});
    }

    bool
    listen(std::string const &uri, std::filesystem::path const &cert_file, std::filesystem::path const &key_file) {
        return listen(qb::io::uri(uri), cert_file, key_file);
    }

    void
    graceful_shutdown() {
        std::vector<std::uint64_t> connection_ids;
        connection_ids.reserve(_connections.size());
        for (auto const &[connection_id, _] : _connections) {
            connection_ids.push_back(connection_id);
        }
        for (auto connection_id : connection_ids) {
            auto *conn = connection(connection_id);
            if (!conn) {
                continue;
            }
            (void) conn->submit_shutdown_notice();
            (void) conn->shutdown();
            _shutdown_connections.insert(connection_id);
            if (conn->is_drained() || !has_active_contexts(connection_id)) {
                close_http3_connection(connection_id, 0, "HTTP/3 graceful shutdown");
            }
        }
    }

    std::uint64_t
    open_http3_unidirectional_stream(std::uint64_t connection_id) {
        return this->open_unidirectional_stream(connection_id).id();
    }

    void
    send_http3_stream_data(std::uint64_t connection_id, std::uint64_t stream_id, std::string_view data, bool fin) {
        this->send_stream_data(connection_id, stream_id, data, fin);
    }

    void
    extend_http3_stream_credit(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t bytes) {
        this->extend_stream_credit(connection_id, stream_id, bytes);
    }

    void
    reset_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t app_error_code) {
        this->reset_stream(connection_id, stream_id, app_error_code);
    }

    void
    stop_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t app_error_code) {
        this->stop_stream(connection_id, stream_id, app_error_code);
    }

    void
    close_http3_connection(std::uint64_t connection_id, std::uint64_t app_error_code, std::string_view reason) {
        this->close_connection(connection_id, app_error_code, reason);
    }

    void
    on_http3_stream_acked(std::uint64_t, std::uint64_t) {}

    void
    on_http3_stream_closed(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t) {
        on_http3_stream_output_drained(connection_id, stream_id);
        stream_key key{connection_id, stream_id};
        _sessions.erase(key);
        maybe_finish_graceful_shutdown(connection_id);
    }

    void
    on_http3_stream_output_drained(std::uint64_t connection_id, std::uint64_t stream_id) {
        stream_key key{connection_id, stream_id};
        if (auto it = _sessions.find(key); it != _sessions.end()) {
            it->second->mark_response_sent();
        }
        maybe_finish_graceful_shutdown(connection_id);
    }

    void
    on_http3_shutdown(std::uint64_t, std::uint64_t) {}

    void
    on_http3_request(std::uint64_t connection_id, std::uint64_t stream_id, qb::http::Request request) {
        auto session      = ensure_session(connection_id, stream_id);
        request.stream_id = stream_id;
        session->bind_http3_request_method(request.method());
        auto context = _router.route(session, std::move(request));
        if (!context) {
            qb::http::Response not_found(qb::http::status::NOT_FOUND);
            not_found.stream_id = stream_id;
            send_response(connection_id, stream_id, not_found);
            return;
        }
        session->attach_context(context);
    }

    bool
    send_response(std::uint64_t connection_id, std::uint64_t stream_id, qb::http::Response const &response) {
        auto &conn = ensure_connection(connection_id);
        if (conn.submit_response(stream_id, response)) {
            maybe_finish_graceful_shutdown(connection_id);
            return true;
        }
        reset_http3_stream(connection_id, stream_id, 0x010e);
        return false;
    }
};

} // namespace internal

template <typename Derived>
struct use {
    template <typename ServerHandler>
    using session = internal::session<Derived, ServerHandler>;

    template <typename SessionType>
    using server = internal::server<Derived, SessionType>;
};

template <typename SessionType>
class Server;

class DefaultSession : public qb::http3::use<DefaultSession>::session<Server<DefaultSession>> {
public:
    using Base = qb::http3::use<DefaultSession>::session<Server<DefaultSession>>;

    explicit DefaultSession(Server<DefaultSession> &server)
        : Base(server) {}
};

template <typename SessionType = DefaultSession>
class Server : public qb::http3::internal::server<Server<SessionType>, SessionType> {
public:
    using Session = SessionType;
    Server()      = default;
};

template <typename Session = DefaultSession>
[[nodiscard]] std::unique_ptr<Server<Session>>
make_server() {
    return std::make_unique<Server<Session>>();
}

template <typename Session = DefaultSession>
using server = Server<Session>;

} // namespace qb::http3

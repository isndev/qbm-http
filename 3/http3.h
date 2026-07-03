/**
 * @file qbm/http/3/http3.h
 * @brief Native HTTP/3 server integration for qbm/http.
 *
 * This header provides the server-side HTTP/3 stack built on top of the QUIC
 * endpoint (`qb::io::async::quic::endpoint`). It wires the QUIC stream lifecycle
 * to the HTTP/3 protocol layer (`qb::protocol::http3::connection`) and the shared
 * routing engine (`qb::http::Router`), exposing a CRTP server/session pair:
 *   - `internal::session` maps a single HTTP/3 request stream onto the routing
 *     `Context`, response serialization, and HEAD handling.
 *   - `internal::server` owns per-connection HTTP/3 state, sessions, graceful
 *     shutdown bookkeeping, and dispatch of QUIC events.
 * The `use`, `Server`, `DefaultSession`, and `make_server` facilities provide the
 * ready-to-use, default-instantiated entry points.
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

/**
 * @brief Composite key identifying a single HTTP/3 request stream.
 *
 * Pairs the owning QUIC connection id with the stream id; used to index the
 * per-stream session map. Equality is member-wise (defaulted).
 */
struct stream_key {
    std::uint64_t connection_id = 0; ///< Owning QUIC connection identifier.
    std::uint64_t stream_id     = 0; ///< Stream identifier within the connection.

    friend bool operator==(stream_key const &, stream_key const &) = default;
};

/**
 * @brief Hash functor for @ref stream_key, suitable for unordered containers.
 */
struct stream_key_hash {
    /**
     * @brief Combine the two key fields into a single hash value.
     * @param key Stream key to hash.
     * @return Combined hash of the connection and stream identifiers.
     */
    std::size_t
    operator()(stream_key const &key) const noexcept {
        auto h1 = std::hash<std::uint64_t>{}(key.connection_id);
        auto h2 = std::hash<std::uint64_t>{}(key.stream_id);
        return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6U) + (h1 >> 2U));
    }
};

/**
 * @brief Per-stream HTTP/3 session bound to the routing engine.
 *
 * Represents a single HTTP/3 request stream. Holds the routing @ref ContextType
 * for the in-flight request, serializes responses back through the owning
 * @p Handler (the HTTP/3 server), applies HEAD semantics, and runs the
 * post-response hook once the response has been flushed.
 *
 * @tparam Derived  Concrete session type (CRTP), enabling shared_from_this.
 * @tparam Handler  HTTP/3 server type providing routing and response transport.
 */
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

    /**
     * @brief Associate this session with its QUIC connection and stream ids.
     * @param connection_id Owning QUIC connection identifier.
     * @param stream_id     Request stream identifier.
     */
    void
    bind_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id) noexcept {
        _connection_id = connection_id;
        _stream_id     = stream_id;
    }

    /**
     * @brief Record the request method, used to apply HEAD response semantics.
     * @param method HTTP method of the in-flight request.
     */
    void
    bind_http3_request_method(qb::http::Method method) noexcept {
        _request_method = method;
    }

    /**
     * @brief Attach the routing context for the in-flight request.
     *
     * If the response was already sent before the context arrived, the
     * post-response-send hook is executed immediately and the context released.
     *
     * @param context Routing context to take ownership of.
     */
    void
    attach_context(std::shared_ptr<ContextType> context) noexcept {
        _context = std::move(context);
        if (_response_sent && _context) {
            _context->execute_hook(qb::http::HookPoint::POST_RESPONSE_SEND);
            _context.reset();
        }
    }

    /**
     * @brief Cancel the in-flight routing context and release it.
     * @param reason Human-readable cancellation reason forwarded to the context.
     */
    void
    cancel_context(std::string const &reason) noexcept {
        if (_context) {
            _context->cancel(reason);
            _context.reset();
        }
    }

    /**
     * @brief Mark the response as fully sent.
     *
     * Idempotent. On the first call, runs the post-response-send hook on the
     * attached context (if any) and releases it.
     */
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

    /**
     * @brief Whether a routing context is currently attached.
     * @return True while a context is in flight, false otherwise.
     */
    [[nodiscard]] bool
    has_active_context() const noexcept {
        return static_cast<bool>(_context);
    }

    /**
     * @brief Serialize and send an HTTP response on this stream.
     *
     * Stamps the response with this stream id, fills in @c content-length when
     * missing and a body is present, and applies HEAD semantics (sends headers
     * with an empty body while still advertising the would-be content length).
     *
     * @param response Response to send; its @c stream_id is overwritten.
     * @return Reference to the session's output pipe.
     */
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

/**
 * @brief CRTP HTTP/3 server bound to a QUIC endpoint.
 *
 * Owns the per-connection HTTP/3 protocol state, the per-stream sessions, and
 * the shared routing engine. Translates QUIC events (connect, stream data,
 * stream/connection close, acknowledgements) into HTTP/3 protocol operations
 * and routed requests, and serializes responses back onto the matching streams.
 * Also implements HTTP/3 graceful shutdown bookkeeping.
 *
 * @tparam Derived     Concrete server type (CRTP), allowing optional user hooks.
 * @tparam SessionType Per-stream session type instantiated for each request.
 */
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
    // >0 while an HTTP/3 read (nghttp3_conn_read_stream2) is on the stack. A request callback
    // reached from that read can synchronously fail a connection — a send larger than the QUIC
    // TX cap makes the backend queue a close and reentrantly deliver dispatch(connection_closed),
    // which schedules the connection into _closed_connections. Erasing (freeing) it while its
    // read is on the stack calls nghttp3_conn_del mid-read (use-after-free), so
    // after_dispatch_events DEFERS the reap while this is >0; dispatch(stream_data) reaps once
    // the outermost read unwinds.
    int                                                                          _read_depth = 0;
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
    // QUIC event dispatch overrides: translate endpoint events into HTTP/3
    // connection/session lifecycle operations. User-provided `Derived::on(ev)`
    // hooks are invoked when present (detected via `requires`).
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
        // Guard the read: a request callback reached from nghttp3_conn_read_stream2 can
        // reentrantly close this (or another) connection. While the read is on the stack the
        // erase is deferred (after_dispatch_events becomes a no-op); reap once it unwinds.
        // `conn` stays valid across the read — _connections holds unique_ptr (heap-stable), so
        // a deferred-but-not-yet-erased connection is not freed here. The RAII guard restores
        // _read_depth on every exit (including an exception escaping read_stream) so a throw
        // cannot wedge the counter ≥1 and leak every future closed connection.
        struct DepthGuard {
            int &d;
            explicit DepthGuard(int &d_) noexcept : d(d_) { ++d; }
            ~DepthGuard() { --d; }
        };
        {
            DepthGuard guard(_read_depth);
            conn.read_stream(ev.id, ev.payload, ev.fin);
        }
        if (_read_depth == 0) {
            reap_closed_connections();
        }
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
        // Defer the reap while an HTTP/3 read is on the stack: this hook runs at the end of
        // EVERY drain_backend_events(), including one re-entered from a send inside
        // nghttp3_conn_read_stream2. Erasing a connection there frees it mid-read (UAF). The
        // outermost dispatch(stream_data) reaps once _read_depth returns to 0.
        if (_read_depth > 0) {
            return;
        }
        reap_closed_connections();
    }

    void
    reap_closed_connections() {
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

    /**
     * @brief Set the maximum accepted request body size.
     * @param value Maximum body size in bytes.
     */
    void
    set_max_body_size(std::size_t value) noexcept {
        _max_body_size = value;
    }
    /**
     * @brief Current maximum accepted request body size, in bytes.
     */
    [[nodiscard]] std::size_t
    max_http3_body_size() const noexcept {
        return _max_body_size;
    }

    /**
     * @brief Start listening for HTTP/3 (QUIC) connections.
     * @param uri       Bind URI (scheme/host/port).
     * @param cert_file Path to the TLS certificate (PEM).
     * @param key_file  Path to the TLS private key (PEM).
     * @return True if the endpoint is now listening, false on failure.
     */
    bool
    listen(qb::io::uri const &uri, std::filesystem::path const &cert_file, std::filesystem::path const &key_file) {
        return qb::io::async::quic::endpoint::listen(uri, cert_file, key_file, {"h3"});
    }

    /**
     * @brief Start listening for HTTP/3 connections from a string URI.
     * @param uri       Bind URI string, parsed into a @c qb::io::uri.
     * @param cert_file Path to the TLS certificate (PEM).
     * @param key_file  Path to the TLS private key (PEM).
     * @return True if the endpoint is now listening, false on failure.
     */
    bool
    listen(std::string const &uri, std::filesystem::path const &cert_file, std::filesystem::path const &key_file) {
        return listen(qb::io::uri(uri), cert_file, key_file);
    }

    /**
     * @brief Begin HTTP/3 graceful shutdown of all connections.
     *
     * Submits a shutdown notice on each connection and closes immediately those
     * already drained or with no active request contexts; the remainder are
     * closed later as their contexts complete.
     */
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

    /**
     * @brief Open a new unidirectional stream on a connection.
     * @param connection_id Target QUIC connection.
     * @return Identifier of the newly opened unidirectional stream.
     */
    std::uint64_t
    open_http3_unidirectional_stream(std::uint64_t connection_id) {
        return this->open_unidirectional_stream(connection_id).id();
    }

    /**
     * @brief Send raw bytes on a stream.
     * @param connection_id Target QUIC connection.
     * @param stream_id     Target stream.
     * @param data          Payload to write.
     * @param fin           Whether this write closes the stream's write side.
     */
    void
    send_http3_stream_data(std::uint64_t connection_id, std::uint64_t stream_id, std::string_view data, bool fin) {
        this->send_stream_data(connection_id, stream_id, data, fin);
    }

    /**
     * @brief Grant additional flow-control credit to a stream.
     * @param connection_id Target QUIC connection.
     * @param stream_id     Target stream.
     * @param bytes         Extra credit to extend, in bytes.
     */
    void
    extend_http3_stream_credit(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t bytes) {
        this->extend_stream_credit(connection_id, stream_id, bytes);
    }

    /**
     * @brief Reset (abort the write side of) a stream.
     * @param connection_id  Target QUIC connection.
     * @param stream_id      Target stream.
     * @param app_error_code Application error code to signal on the stream.
     */
    void
    reset_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t app_error_code) {
        this->reset_stream(connection_id, stream_id, app_error_code);
    }

    /**
     * @brief Request the peer stop sending on a stream (abort the read side).
     * @param connection_id  Target QUIC connection.
     * @param stream_id      Target stream.
     * @param app_error_code Application error code to signal on the stream.
     */
    void
    stop_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t app_error_code) {
        this->stop_stream(connection_id, stream_id, app_error_code);
    }

    /**
     * @brief Close a connection with an application error code.
     * @param connection_id  Target QUIC connection.
     * @param app_error_code Application error code (0 for a clean close).
     * @param reason         Human-readable close reason.
     */
    void
    close_http3_connection(std::uint64_t connection_id, std::uint64_t app_error_code, std::string_view reason) {
        this->close_connection(connection_id, app_error_code, reason);
    }

    /**
     * @brief Protocol callback: stream data acknowledged by the peer.
     *
     * Default no-op; provided as a customization point.
     */
    void
    on_http3_stream_acked(std::uint64_t, std::uint64_t) {}

    /**
     * @brief Protocol callback: a stream has been closed.
     *
     * Flushes any pending response-sent bookkeeping, erases the session, and
     * advances graceful shutdown if it is in progress.
     *
     * @param connection_id Owning QUIC connection.
     * @param stream_id     Closed stream.
     */
    void
    on_http3_stream_closed(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t) {
        on_http3_stream_output_drained(connection_id, stream_id);
        stream_key key{connection_id, stream_id};
        _sessions.erase(key);
        maybe_finish_graceful_shutdown(connection_id);
    }

    /**
     * @brief Protocol callback: a stream's output buffer has fully drained.
     *
     * Marks the matching session's response as sent and advances graceful
     * shutdown if it is in progress.
     *
     * @param connection_id Owning QUIC connection.
     * @param stream_id     Drained stream.
     */
    void
    on_http3_stream_output_drained(std::uint64_t connection_id, std::uint64_t stream_id) {
        stream_key key{connection_id, stream_id};
        if (auto it = _sessions.find(key); it != _sessions.end()) {
            it->second->mark_response_sent();
        }
        maybe_finish_graceful_shutdown(connection_id);
    }

    /**
     * @brief Protocol callback: peer-initiated shutdown notice.
     *
     * Default no-op; provided as a customization point.
     */
    void
    on_http3_shutdown(std::uint64_t, std::uint64_t) {}

    /**
     * @brief Protocol callback: a complete HTTP/3 request was received.
     *
     * Resolves (or creates) the session for the stream, routes the request, and
     * either attaches the produced context or sends a 404 when no route matches.
     *
     * @param connection_id Owning QUIC connection.
     * @param stream_id     Request stream.
     * @param request       Parsed HTTP request (consumed by routing).
     */
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

    /**
     * @brief Encode and submit an HTTP response onto a stream.
     *
     * On submission failure the stream is reset; on success, graceful shutdown
     * progress is re-evaluated.
     *
     * @param connection_id Owning QUIC connection.
     * @param stream_id     Target stream.
     * @param response      Response to encode and send.
     * @return True if the response was submitted, false if the stream was reset.
     */
    bool
    send_response(std::uint64_t connection_id, std::uint64_t stream_id, qb::http::Response const &response) {
        // Lookup-only, NOT ensure_connection(): if the connection was reaped (peer closed) before the
        // app produced its response, drop the response. Resurrecting it via create-if-absent would
        // emplace a dead entry and bind_local_streams() on a nonexistent QUIC connection (a zombie
        // that never reaps), or open control streams on whichever connection now holds that id.
        auto *conn = connection(connection_id);
        if (!conn) {
            return false;
        }
        if (conn->submit_response(stream_id, response)) {
            maybe_finish_graceful_shutdown(connection_id);
            return true;
        }
        reset_http3_stream(connection_id, stream_id, 0x010e);
        return false;
    }
};

} // namespace internal

/**
 * @brief CRTP helper exposing the session/server templates for a user type.
 *
 * Lets a user-defined @p Derived type select the HTTP/3 session and server base
 * classes via convenient member aliases.
 *
 * @tparam Derived User type deriving the HTTP/3 server or session.
 */
template <typename Derived>
struct use {
    /// HTTP/3 session base bound to @p Derived and the given server handler.
    template <typename ServerHandler>
    using session = internal::session<Derived, ServerHandler>;

    /// HTTP/3 server base bound to @p Derived and the given session type.
    template <typename SessionType>
    using server = internal::server<Derived, SessionType>;
};

template <typename SessionType>
class Server;

/**
 * @brief Default HTTP/3 session used by @ref Server when none is supplied.
 */
class DefaultSession : public qb::http3::use<DefaultSession>::session<Server<DefaultSession>> {
public:
    using Base = qb::http3::use<DefaultSession>::session<Server<DefaultSession>>;

    explicit DefaultSession(Server<DefaultSession> &server)
        : Base(server) {}
};

/**
 * @brief Ready-to-use HTTP/3 server.
 * @tparam SessionType Per-stream session type (defaults to @ref DefaultSession).
 */
template <typename SessionType = DefaultSession>
class Server : public qb::http3::internal::server<Server<SessionType>, SessionType> {
public:
    using Session = SessionType;
    Server()      = default;
};

/**
 * @brief Construct a default-configured HTTP/3 server.
 * @tparam Session Per-stream session type (defaults to @ref DefaultSession).
 * @return Owning pointer to a new @ref Server instance.
 */
template <typename Session = DefaultSession>
[[nodiscard]] std::unique_ptr<Server<Session>>
make_server() {
    return std::make_unique<Server<Session>>();
}

/// Convenience lowercase alias for @ref Server.
template <typename Session = DefaultSession>
using server = Server<Session>;

} // namespace qb::http3

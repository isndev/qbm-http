/**
 * @file qbm/http/3/client.h
 * @brief HTTP/3 client API.
 */
#pragma once

#ifndef QBM_HTTP_HAS_HTTP3
#error "HTTP/3 support is not enabled. Build qbm/http with QBM_HTTP_HAS_HTTP3."
#endif

#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <qb/io/async.h>
#include <qb/io/async/quic/endpoint.h>
#include <qb/system/container/unordered_map.h>
#include <qb/uuid.h>

#include "../coro.h"
#include "../request.h"
#include "../response.h"
#include "protocol/connection.h"

namespace qb::http3 {

using ResponseCallback      = std::function<void(qb::http::Response)>;
using BatchResponseCallback = std::function<void(std::vector<qb::http::Response>)>;
using ConnectionCallback    = std::function<void(bool connected, const std::string &error_message)>;
using request_id            = std::uint64_t;

struct ConnectResult {
    bool        ok{false};
    std::string error_message;

    explicit
    operator bool() const noexcept {
        return ok;
    }
};

struct RequestContext {
    qb::http::Request                     request;
    ResponseCallback                      callback;
    std::chrono::steady_clock::time_point created_at;
    qb::http3::request_id                 request_id = 0;
    std::uint64_t                         stream_id  = 0;
    std::uint64_t                         batch_id   = 0;
};

struct BatchRequestContext {
    BatchResponseCallback           callback;
    std::vector<qb::http::Response> responses;
    std::vector<bool>               completed;
    std::size_t                     completed_count = 0;
};

class Client
    : public std::enable_shared_from_this<Client>
    , public qb::io::async::quic::endpoint {
public:
    using h3_connection = qb::protocol::http3::connection<Client>;

private:
    qb::io::uri _base_uri;
    qb::uuid    _client_id;
    std::string _host;
    bool        _is_connected    = false;
    bool        _is_connecting   = false;
    bool        _h3_ready        = false;
    bool        _remote_shutdown = false;

    std::unique_ptr<h3_connection>                                         _h3;
    std::deque<std::unique_ptr<RequestContext>>                            _pending_requests;
    qb::unordered_map<std::uint64_t, std::unique_ptr<RequestContext>>      _active_requests;
    qb::unordered_map<std::uint64_t, std::unique_ptr<BatchRequestContext>> _active_batches;
    std::uint64_t                                                          _next_request_id = 1;
    std::uint64_t                                                          _next_batch_id   = 1;

    std::size_t                     _max_concurrent_streams = 100;
    std::size_t                     _max_pending_requests   = 10000; ///< Cap on queued+active requests (bounds _pending_requests)
    std::size_t                     _max_body_size          = 64 * 1024 * 1024;
    qb::duration                    _connect_timeout        = std::chrono::seconds(30);
    qb::duration                    _request_timeout        = std::chrono::seconds(60);
    bool                            _auto_reconnect         = true;
    bool                            _verify_peer            = true;
    std::vector<ConnectionCallback> _connection_callbacks;

    std::uint64_t _total_requests      = 0;
    std::uint64_t _successful_requests = 0;
    std::uint64_t _failed_requests     = 0;

public:
    explicit Client(std::string const &base_uri);
    explicit Client(qb::io::uri const &uri);
    ~Client();

    Client(Client const &)            = delete;
    Client &operator=(Client const &) = delete;

    bool                                                  connect(ConnectionCallback callback);
    [[nodiscard]] qb::http::async::awaiter<ConnectResult> connect();
    void                                                  disconnect();

    [[nodiscard]] bool
    is_connected() const noexcept {
        return _is_connected && _h3_ready;
    }
    [[nodiscard]] bool
    is_connecting() const noexcept {
        return _is_connecting;
    }

    bool                     push_request(qb::http::Request request, ResponseCallback callback);
    [[nodiscard]] request_id push_request_with_id(qb::http::Request request, ResponseCallback callback);
    bool                     cancel_request(request_id id, std::string const &reason = "HTTP/3 request cancelled");
    [[nodiscard]] qb::http::async::awaiter<qb::http::Response> push_request(qb::http::Request request);
    bool push_requests(std::vector<qb::http::Request> requests, BatchResponseCallback callback);
    [[nodiscard]] qb::http::async::awaiter<std::vector<qb::http::Response>> push_requests(std::vector<qb::http::Request> requests);

    void
    set_max_concurrent_streams(std::size_t value) noexcept {
        _max_concurrent_streams = value;
    }
    void
    set_max_body_size(std::size_t value) noexcept {
        _max_body_size = value;
    }
    void
    set_connect_timeout(qb::duration value) noexcept {
        _connect_timeout = value;
    }
    void
    set_request_timeout(qb::duration value) noexcept {
        _request_timeout = value;
    }
    void
    set_auto_reconnect(bool value) noexcept {
        _auto_reconnect = value;
    }
    void
    set_verify_peer(bool value) noexcept {
        _verify_peer = value;
    }

    [[nodiscard]] std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>
    get_stats() const noexcept {
        return {_total_requests, _successful_requests, _failed_requests};
    }

    [[nodiscard]] std::size_t
    get_active_request_count() const noexcept {
        return _active_requests.size();
    }

    [[nodiscard]] std::size_t
    max_http3_body_size() const noexcept {
        return _max_body_size;
    }
    [[nodiscard]] qb::io::uri const &
    get_base_uri() const noexcept {
        return _base_uri;
    }

    std::uint64_t open_http3_unidirectional_stream(std::uint64_t connection_id);
    void          send_http3_stream_data(std::uint64_t connection_id, std::uint64_t stream_id, std::string_view data, bool fin);
    void          extend_http3_stream_credit(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t bytes);
    void          reset_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t app_error_code);
    void          stop_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t app_error_code);
    void          close_http3_connection(std::uint64_t connection_id, std::uint64_t app_error_code, std::string_view reason);
    void          on_http3_stream_acked(std::uint64_t stream_id, std::uint64_t bytes);
    void          on_http3_stream_closed(std::uint64_t stream_id, std::uint64_t app_error_code);
    void          on_http3_shutdown(std::uint64_t connection_id, std::uint64_t last_stream_id);
    void          on_http3_response(std::uint64_t stream_id, qb::http::Response response);

protected:
    void dispatch(qb::io::async::quic::event::connected const &ev) override;
    void dispatch(qb::io::async::quic::event::connection_closed const &ev) override;
    void dispatch(qb::io::async::quic::event::stream_data const &ev) override;
    void dispatch(qb::io::async::quic::event::stream_data_acked const &ev) override;
    void dispatch(qb::io::async::quic::event::stream_closed const &ev) override;

private:
    void                                            initialize_from_uri(qb::io::uri const &uri);
    void                                            ensure_absolute_uri(qb::http::Request &request);
    [[nodiscard]] std::optional<qb::http::Response> prepare_request(qb::http::Request &request);
    void                                            process_pending_requests();
    void                                            handle_connection_success(std::string const &alpn);
    void                                            handle_connection_failure(std::string const &error);
    void                                            fail_all_requests(std::string const &error);
    void fail_request(std::uint64_t stream_id, std::string const &error, qb::http::status status = qb::http::status::BAD_GATEWAY);
    void fail_pending_request(std::uint64_t request_id, std::string const &error, qb::http::status status = qb::http::status::BAD_GATEWAY);
    void arm_connect_timeout();
    void arm_request_timeout(std::uint64_t request_id);
    [[nodiscard]] bool               has_pending_or_active_work() const noexcept;
    [[nodiscard]] qb::http::Response create_error_response(qb::http::status status, std::string const &message);
};

using client = Client;

std::shared_ptr<Client> make_client(std::string const &base_uri);
std::shared_ptr<Client> make_client(qb::io::uri const &uri);

} // namespace qb::http3

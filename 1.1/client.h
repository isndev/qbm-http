/**
 * @file qbm/http/1.1/client.h
 * @brief Persistent HTTP/1.1 client API.
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
#include "../request.h"
#include "../response.h"
#include "../logger.h"
#include "./protocol/client.h"

namespace qb::http1 {

using ResponseCallback = std::function<void(qb::http::Response)>;
using BatchResponseCallback = std::function<void(std::vector<qb::http::Response>)>;
using ConnectionCallback = std::function<void(bool connected, const std::string& error_message)>;

struct ConnectResult {
    bool ok{false};
    std::string error_message;

    explicit operator bool() const noexcept { return ok; }
};

struct RequestContext {
    std::uint64_t request_id = 0;
    qb::http::Request request;
    ResponseCallback callback;
    std::chrono::steady_clock::time_point created_at;
};

struct BatchRequestContext {
    BatchResponseCallback callback;
    std::vector<qb::http::Response> responses;
    std::size_t completed_count = 0;
};

class Client : public std::enable_shared_from_this<Client> {
    class callback_scope;

    class connection_base {
    public:
        virtual ~connection_base() = default;
        virtual void connect(qb::io::uri const& uri, double timeout) = 0;
        virtual void disconnect() = 0;
        virtual void send(qb::http::Request request, double timeout) = 0;
        [[nodiscard]] virtual bool is_open() const noexcept = 0;
    };

    template <typename Transport>
    class connection;

    qb::io::uri _base_uri;
    std::string _host;
    bool _is_connected = false;
    bool _is_connecting = false;
    bool _intentional_disconnect = false;
    bool _reconnect_after_disconnect = false;
    std::shared_ptr<Client> _callback_self_guard;
    std::size_t _callback_depth = 0;
    bool _deferred_connection_reset = false;

    std::unique_ptr<connection_base> _connection;
    std::deque<std::unique_ptr<RequestContext>> _pending_requests;
    std::unique_ptr<RequestContext> _active_request;
    qb::unordered_map<std::uint64_t, std::unique_ptr<BatchRequestContext>> _active_batches;
    std::uint64_t _next_request_id = 1;
    std::uint64_t _next_batch_id = 1;

    double _connect_timeout = 30.0;
    double _request_timeout = 60.0;
    std::size_t _max_pending_requests = 1024;
    bool _auto_reconnect = true;
    std::vector<ConnectionCallback> _connection_callbacks;

    std::uint64_t _total_requests = 0;
    std::uint64_t _successful_requests = 0;
    std::uint64_t _failed_requests = 0;

public:
    explicit Client(std::string const& base_uri);
    explicit Client(qb::io::uri const& uri);
    ~Client();

    Client(Client const&) = delete;
    Client& operator=(Client const&) = delete;

    bool connect(ConnectionCallback callback);
    [[nodiscard]] qb::http::async::awaiter<ConnectResult> connect();
    void disconnect();

    [[nodiscard]] bool is_connected() const noexcept { return _is_connected; }
    [[nodiscard]] bool is_connecting() const noexcept { return _is_connecting; }

    bool push_request(qb::http::Request request, ResponseCallback callback);
    [[nodiscard]] qb::http::async::awaiter<qb::http::Response> push_request(qb::http::Request request);
    bool push_requests(std::vector<qb::http::Request> requests, BatchResponseCallback callback);
    [[nodiscard]] qb::http::async::awaiter<std::vector<qb::http::Response>>
    push_requests(std::vector<qb::http::Request> requests);

    void set_connect_timeout(double value) noexcept { _connect_timeout = value; }
    void set_request_timeout(double value) noexcept { _request_timeout = value; }
    void set_auto_reconnect(bool value) noexcept { _auto_reconnect = value; }
    void set_max_pending_requests(std::size_t value) noexcept { _max_pending_requests = value; }

    [[nodiscard]] std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>
    get_stats() const noexcept {
        return {_total_requests, _successful_requests, _failed_requests};
    }

    [[nodiscard]] std::size_t get_active_request_count() const noexcept {
        return _active_request ? 1u : 0u;
    }

    [[nodiscard]] qb::io::uri const& get_base_uri() const noexcept { return _base_uri; }

private:
    void initialize_from_uri(qb::io::uri const& uri);
    void create_connection();
    void ensure_absolute_uri(qb::http::Request& request);
    [[nodiscard]] std::optional<qb::http::Response> prepare_request(qb::http::Request& request);
    void hold_through_current_tick();
    void enter_user_callback();
    void leave_user_callback() noexcept;
    void reset_deferred_connection_if_ready();
    void process_pending_requests();
    void arm_pending_timeout(std::uint64_t request_id);
    bool fail_pending_request(std::uint64_t request_id,
                              std::string const& error,
                              qb::http::status status = qb::http::status::REQUEST_TIMEOUT);
    void handle_connection_success();
    void handle_connection_failure(std::string const& error);
    void handle_response(qb::http::Response response);
    void handle_timeout();
    void handle_disconnected(int reason);
    void fail_active_request(std::string const& error,
                             qb::http::status status = qb::http::status::BAD_GATEWAY);
    void fail_all_requests(std::string const& error,
                           qb::http::status status = qb::http::status::SERVICE_UNAVAILABLE);
    [[nodiscard]] bool has_pending_work() const noexcept;
    [[nodiscard]] qb::http::Response create_error_response(qb::http::status status,
                                                           std::string const& message);
};

using client = Client;

std::shared_ptr<Client> make_client(std::string const& base_uri);
std::shared_ptr<Client> make_client(qb::io::uri const& uri);

} // namespace qb::http1

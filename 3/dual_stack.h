/**
 * @file qbm/http/3/dual_stack.h
 * @brief Convenience HTTP/2 + HTTP/3 server wrapper.
 */
#pragma once

#ifndef QBM_HTTP_HAS_HTTP3
#error "HTTP/3 support is not enabled. Build qbm/http with QBM_HTTP_HAS_HTTP3."
#endif

#include <filesystem>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

#include "../2/http2.h"
#include "./http3.h"

namespace qb::http {

template <typename Http2Session = qb::http2::DefaultSession, typename Http3Session = qb::http3::DefaultSession>
class dual_stack_server {
public:
    using http2_server_type = qb::http2::Server<Http2Session>;
    using http3_server_type = qb::http3::Server<Http3Session>;

    class router_facade {
        dual_stack_server *_owner = nullptr;

        template <typename Handler>
        router_facade &
        add_to_both(std::string path, qb::http::method verb, Handler &&handler) {
            using stored_handler = std::decay_t<Handler>;
            auto shared          = std::make_shared<stored_handler>(std::forward<Handler>(handler));
            _owner->_http2->router().add_route(path, verb, [shared](auto ctx) { (*shared)(std::move(ctx)); });
            _owner->_http3->router().add_route(std::move(path), verb, [shared](auto ctx) { (*shared)(std::move(ctx)); });
            return *this;
        }

    public:
        explicit router_facade(dual_stack_server &owner) noexcept
            : _owner(&owner) {}

        template <typename Handler>
        router_facade &
        add_route(std::string path, qb::http::method verb, Handler &&handler) {
            return add_to_both(std::move(path), verb, std::forward<Handler>(handler));
        }

        template <typename Handler>
        router_facade &
        get(std::string path, Handler &&handler) {
            return add_to_both(std::move(path), qb::http::method::GET, std::forward<Handler>(handler));
        }

        template <typename Handler>
        router_facade &
        post(std::string path, Handler &&handler) {
            return add_to_both(std::move(path), qb::http::method::POST, std::forward<Handler>(handler));
        }

        template <typename Handler>
        router_facade &
        put(std::string path, Handler &&handler) {
            return add_to_both(std::move(path), qb::http::method::PUT, std::forward<Handler>(handler));
        }

        template <typename Handler>
        router_facade &
        del(std::string path, Handler &&handler) {
            return add_to_both(std::move(path), qb::http::method::DEL, std::forward<Handler>(handler));
        }

        template <typename Handler>
        router_facade &
        patch(std::string path, Handler &&handler) {
            return add_to_both(std::move(path), qb::http::method::PATCH, std::forward<Handler>(handler));
        }

        template <typename Handler>
        router_facade &
        options(std::string path, Handler &&handler) {
            return add_to_both(std::move(path), qb::http::method::OPTIONS, std::forward<Handler>(handler));
        }

        template <typename Handler>
        router_facade &
        head(std::string path, Handler &&handler) {
            return add_to_both(std::move(path), qb::http::method::HEAD, std::forward<Handler>(handler));
        }

        void
        compile() {
            _owner->_http2->router().compile();
            _owner->_http3->router().compile();
        }
    };

private:
    std::unique_ptr<http2_server_type> _http2;
    std::unique_ptr<http3_server_type> _http3;
    router_facade                      _router;

public:
    dual_stack_server()
        : _http2(qb::http2::make_server<Http2Session>())
        , _http3(qb::http3::make_server<Http3Session>())
        , _router(*this) {}

    [[nodiscard]] router_facade &
    router() noexcept {
        return _router;
    }
    [[nodiscard]] http2_server_type &
    http2_server() noexcept {
        return *_http2;
    }
    [[nodiscard]] http3_server_type &
    http3_server() noexcept {
        return *_http3;
    }

    bool
    listen(qb::io::uri tcp_tls_uri, qb::io::uri quic_uri, std::filesystem::path const &cert_file, std::filesystem::path const &key_file) {
        const bool tcp_ok = _http2->listen(std::move(tcp_tls_uri), cert_file, key_file);
        if (tcp_ok) {
            _http2->start();
        }
        const bool quic_ok = _http3->listen(std::move(quic_uri), cert_file, key_file);
        return tcp_ok && quic_ok;
    }

    bool
    listen(std::string const &tcp_tls_uri, std::string const &quic_uri, std::filesystem::path const &cert_file,
           std::filesystem::path const &key_file) {
        return listen(qb::io::uri(tcp_tls_uri), qb::io::uri(quic_uri), cert_file, key_file);
    }

    void
    close_http2() {
        _http2->stop();
        _http2->transport().close();
    }

    void
    close_http3() {
        _http3->close();
    }

    void
    close() {
        close_http3();
        close_http2();
    }
};

template <typename Http2Session = qb::http2::DefaultSession, typename Http3Session = qb::http3::DefaultSession>
[[nodiscard]] std::unique_ptr<dual_stack_server<Http2Session, Http3Session>>
make_dual_stack_server() {
    return std::make_unique<dual_stack_server<Http2Session, Http3Session>>();
}

} // namespace qb::http

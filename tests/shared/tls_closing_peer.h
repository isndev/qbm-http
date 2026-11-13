/**
 * @file qbm/http/tests/shared/tls_closing_peer.h
 * @brief A TLS peer, ALPN h2, that ends every connection once its TLS handshake is complete (Huly QB-1246).
 *
 * The HTTP/2 client's connector drives the TLS handshake and hands over a live transport; with this peer the first thing
 * the client reads on it is its end -- before any octet of HTTP/2, while the client is still connecting.
 *
 * Header-only, test-only. Contains no TEST()/main().
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <qb/io/tcp/ssl/listener.h>
#include <qb/io/tcp/ssl/socket.h>

#include "./ssl_test_resource.h"

namespace qb::http::test {

/// On its own thread: accepts each connection, completes its TLS handshake and closes it at once, `connections` times --
/// on `port`, or on a port of its own when it is 0 -- offering `alpn` (`http/1.1` alone: a peer that speaks no h2), and
/// holding each connection for `hold` first, reading nothing (an h2 peer that never sends its SETTINGS meanwhile).
class TlsClosingPeer {
public:
    explicit TlsClosingPeer(int const connections, std::uint16_t const port = 0, std::vector<std::string> alpn = {"h2"},
                            std::chrono::milliseconds const hold = std::chrono::milliseconds::zero())
        : _connections(connections)
        , _hold(hold) {
        // TLS 1.2 at most: a TLS 1.3 server writes its session tickets after the handshake, and a client that reads them
        // before the end sees a readable socket with no data, completes its handshake event and connects.
        _listener.init(
            qb::io::ssl::Context::server(ssl_cert_path(), ssl_key_path()).alpn(std::move(alpn)).max_version(qb::io::ssl::TlsVersion::v1_2));
        if (_listener.listen_v4(port, "127.0.0.1") != 0)
            return;
        _listener.set_nonblocking(true);
        _port   = _listener.local_endpoint().port();
        _thread = std::thread([this] { run(); });
    }
    ~TlsClosingPeer() {
        _release = true;
        if (_thread.joinable())
            _thread.join();
    }
    TlsClosingPeer(TlsClosingPeer const &)            = delete;
    TlsClosingPeer &operator=(TlsClosingPeer const &) = delete;

    [[nodiscard]] std::uint16_t
    port() const noexcept {
        return _port;
    }

    /// The connections it ended once their TLS handshake was complete.
    [[nodiscard]] int
    ended() const noexcept {
        return _ended.load();
    }

    /// The connections it accepted, ended or not.
    [[nodiscard]] int
    accepted() const noexcept {
        return _accepted.load();
    }

private:
    void
    run() {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
        while (_ended.load() < _connections && !_release && std::chrono::steady_clock::now() < deadline) {
            qb::io::tcp::ssl::socket socket;
            if (_listener.accept(socket) != 0 || !socket.is_open()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            ++_accepted;
            socket.set_nonblocking(true);
            while (!socket.handshake_complete() && !_release && std::chrono::steady_clock::now() < deadline) {
                if (socket.do_handshake() < 0)
                    break;
                if (!socket.handshake_complete())
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            for (const auto until = std::chrono::steady_clock::now() + _hold;
                 socket.handshake_complete() && !_release && std::chrono::steady_clock::now() < until;)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            if (socket.handshake_complete())
                ++_ended; // counted before the client can read the end
            socket.close();
        }
    }

    qb::io::tcp::ssl::listener _listener;
    std::uint16_t              _port = 0;
    int const                  _connections;
    std::chrono::milliseconds  _hold;
    std::atomic<int>           _ended{0};
    std::atomic<int>           _accepted{0};
    std::atomic<bool>          _release{false};
    std::thread                _thread; // last: started once every member it reads is built
};

} // namespace qb::http::test

/**
 * @file qbm/http/tests/shared/ws_loopback.h
 * @brief Shared WebSocket loopback harness for the qbm-http system test suite.
 *
 * The WebSocket system tests run a real qb-io server on a background thread and
 * talk to it over a loopback TCP socket — sometimes a real @c coro_client,
 * sometimes a hand-driven raw socket so the test controls the exact bytes on the
 * wire. This header reconciles the per-file inline copies of that machinery into
 * one canonical set:
 *
 *   - @ref WsServerThread<ServerT> — spins up @c ServerT on its own event loop
 *     thread (init / listen_v4 / start / run-loop / clean shutdown). An optional
 *     @c config callback lets a test tweak the server before it starts
 *     listening. The ctor blocks until the listener is ready.
 *   - @ref perform_upgrade — sends a raw HTTP/1.1 @c Upgrade: websocket request
 *     over a connected socket and asserts the server answered @c 101.
 *   - @ref make_client_frame — builds one masked client→server WebSocket frame
 *     (FIN/RSV/opcode byte, masked 7-bit length, deterministic 4-byte mask,
 *     XOR-masked payload). Payloads are kept ≤125 bytes on purpose.
 *   - @ref read_http_response — polls a socket until the CRLFCRLF header
 *     terminator arrives (or the poll budget is exhausted) and returns the bytes.
 *   - @ref read_some / @ref extract_close_code — small wire helpers for reading
 *     a server frame and decoding an unmasked Close status code.
 *
 * The generic non-WS server fixture (and its @c pump_until) lives in
 * @c shared/loopback_server.h; this header stays focused on the WebSocket
 * upgrade + frame machinery and does not duplicate it. Everything here is
 * header-only and inline so multiple system-test TUs can include it without ODR
 * hazards. Contains no TEST()/main().
 *
 * Reconciled from the inline copies that previously lived in:
 *   - tests/system/ws/ws-framing-edge.cpp
 *       (WsServerThread w/ config callback, make_client_frame, perform_upgrade,
 *        read_some, extract_close_code)
 *   - tests/system/ws/ws-coro-server.cpp   (WsServerThread, read_http_response)
 *   - tests/system/ws/ws-coro-client.cpp   (WsServerThread)
 *   - tests/test-ws-coro-negative.cpp      (WsServerThread)
 *   - tests/test-ws-security.cpp           (read_http_response shape)
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#ifndef QBM_HTTP_TESTS_SHARED_WS_LOOPBACK_H
#define QBM_HTTP_TESTS_SHARED_WS_LOOPBACK_H

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "../ws/coro.h"

namespace qb::http::test {

using namespace std::chrono_literals;

// ===========================================================================
// Background loopback server
// ===========================================================================

/**
 * @brief Run @c ServerT on its own qb-io event-loop thread for loopback tests.
 *
 * The ctor initializes the async loop, constructs the server, applies an
 * optional @p config callback (e.g. to set per-server limits before it accepts
 * connections), binds @p port_ on IPv4, starts it, then pumps the loop until the
 * dtor flips @c running. It blocks until the listener is ready (plus a short
 * settle delay) so a client connecting right after construction won't race the
 * bind.
 *
 * @tparam ServerT a @c qb::io::use<...>::tcp::server<...> session host.
 */
template <typename ServerT>
struct WsServerThread {
    std::thread       thread;
    std::atomic<bool> ready{false};
    std::atomic<bool> running{true};
    int               port{0};

    explicit WsServerThread(int port_, std::function<void(ServerT &)> config = {})
        : port(port_) {
        thread = std::thread([this, config = std::move(config)] {
            qb::io::async::init();
            ServerT server;
            if (config) {
                config(server);
            }
            server.transport().listen_v4(static_cast<std::uint16_t>(port));
            // When the caller asked for an ephemeral port (port == 0), read the
            // kernel-assigned port back from the now-bound listener and publish it
            // BEFORE flipping `ready`, so the main thread (which reads `port`
            // only after observing `ready`) sees the real port instead of 0.
            port = static_cast<int>(server.transport().local_endpoint().port());
            server.start();
            ready.store(true, std::memory_order_release);
            while (running.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(5ms);
                }
            }
        });
        while (!ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(5ms);
        }
        std::this_thread::sleep_for(30ms);
    }

    ~WsServerThread() {
        running.store(false, std::memory_order_release);
        if (thread.joinable()) {
            thread.join();
        }
    }

    WsServerThread(const WsServerThread &)            = delete;
    WsServerThread &operator=(const WsServerThread &) = delete;
};

// ===========================================================================
// Raw HTTP/1.1 upgrade
// ===========================================================================

/**
 * @brief Drive a raw HTTP/1.1 WebSocket upgrade over @p sock and assert @c 101.
 *
 * Sends a fixed, RFC-6455-valid @c Upgrade request (sample key
 * @c dGhlIHNhbXBsZSBub25jZQ==), drains the response header block up to the
 * CRLFCRLF terminator, and ASSERTs the status line contains @c 101. After this
 * returns the socket is in WebSocket framing mode.
 *
 * @param sock a connected, non-blocking loopback socket.
 * @param port server port (used only to build the @c Host header).
 * @param path request-target for the upgrade (defaults to @c "/").
 */
inline void
perform_upgrade(qb::io::tcp::socket &sock, int port, std::string_view path = "/") {
    const std::string port_s  = std::to_string(port);
    std::string       upgrade = "GET ";
    upgrade += path;
    upgrade += " HTTP/1.1\r\n"
               "Host: localhost:";
    upgrade += port_s;
    upgrade += "\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
               "Sec-WebSocket-Version: 13\r\n"
               "\r\n";
    sock.write(upgrade.data(), static_cast<int>(upgrade.size()));

    std::string response;
    for (int i = 0; i < 500; ++i) {
        char buf[512];
        int  n = sock.read(buf, sizeof(buf));
        if (n > 0) {
            response.append(buf, static_cast<std::size_t>(n));
        }
        if (response.find("\r\n\r\n") != std::string::npos) {
            break;
        }
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_NE(response.find("101"), std::string::npos) << "handshake failed:\n" << response;
}

/**
 * @brief Poll @p sock until the CRLFCRLF header terminator arrives.
 *
 * Returns the accumulated bytes (which include the status line and headers, and
 * possibly the start of the body / first frame). Stops after a bounded number of
 * polls so a stuck server fails the test instead of hanging forever.
 */
[[nodiscard]] inline std::string
read_http_response(qb::io::tcp::socket &sock) {
    std::string response;
    for (int i = 0; i < 500 && response.find("\r\n\r\n") == std::string::npos; ++i) {
        char buf[512];
        int  n = sock.read(buf, sizeof(buf));
        if (n > 0) {
            response.append(buf, static_cast<std::size_t>(n));
        } else {
            std::this_thread::sleep_for(5ms);
        }
    }
    return response;
}

// ===========================================================================
// Client-side frame builders / readers
// ===========================================================================

/**
 * @brief Build one masked client→server WebSocket frame.
 *
 * Layout: [FIN|RSV|opcode][MASK|len7][mask4][masked payload]. @p opcode_with_flags
 * is the full first byte (e.g. @c 0x81 = FIN+text, @c 0x89 = FIN+ping). The mask
 * is a fixed, predictable 4-byte value so frames are deterministic. Payloads must
 * be ≤125 bytes (the 7-bit length form) — this is asserted.
 */
[[nodiscard]] inline std::vector<std::uint8_t>
make_client_frame(std::uint8_t opcode_with_flags, std::string_view payload) {
    std::vector<std::uint8_t> out;
    out.reserve(payload.size() + 14);
    out.push_back(opcode_with_flags);

    EXPECT_LE(payload.size(), 125u);
    out.push_back(static_cast<std::uint8_t>(0x80u | payload.size()));

    const std::array<std::uint8_t, 4> mask{{0xAA, 0x55, 0x01, 0xFE}};
    for (auto b : mask) {
        out.push_back(b);
    }
    for (std::size_t i = 0; i < payload.size(); ++i) {
        out.push_back(static_cast<std::uint8_t>(static_cast<std::uint8_t>(payload[i]) ^ mask[i & 3u]));
    }
    return out;
}

/**
 * @brief Read up to @p max bytes from @p sock, polling to tolerate loop cadence.
 *
 * Returns whatever arrived before @p deadline elapses or the peer closes.
 */
[[nodiscard]] inline std::string
read_some(qb::io::tcp::socket &sock, std::size_t max, std::chrono::milliseconds deadline = 1500ms) {
    std::string out;
    const auto  start = std::chrono::steady_clock::now();
    char        buf[256];
    while (out.size() < max && std::chrono::steady_clock::now() - start < deadline) {
        int n = sock.read(buf, sizeof(buf));
        if (n > 0) {
            out.append(buf, static_cast<std::size_t>(n));
        } else if (n == 0) {
            break;
        } else {
            std::this_thread::sleep_for(5ms);
        }
    }
    return out;
}

/**
 * @brief Decode the 16-bit Close status code from a server→client Close frame.
 *
 * Returns @c std::nullopt if @p frame_bytes is not a well-formed, unmasked Close
 * frame with at least a 2-byte status code payload. Handles the 7-bit and 16-bit
 * (126) length forms; the 64-bit (127) form is treated as unexpected for Close.
 */
[[nodiscard]] inline std::optional<std::uint16_t>
extract_close_code(const std::string &frame_bytes) {
    if (frame_bytes.size() < 2u) {
        return std::nullopt;
    }
    const auto b0 = static_cast<std::uint8_t>(frame_bytes[0]);
    const auto b1 = static_cast<std::uint8_t>(frame_bytes[1]);
    if ((b0 & 0x0Fu) != 0x08u) {
        return std::nullopt; // not a Close frame
    }
    if ((b1 & 0x80u) != 0u) {
        return std::nullopt; // server->client Close must be unmasked
    }

    std::size_t payload_len = static_cast<std::size_t>(b1 & 0x7Fu);
    std::size_t header_len  = 2u;
    if (payload_len == 126u) {
        if (frame_bytes.size() < 4u) {
            return std::nullopt;
        }
        payload_len = (static_cast<std::size_t>(static_cast<std::uint8_t>(frame_bytes[2])) << 8u)
                      | static_cast<std::size_t>(static_cast<std::uint8_t>(frame_bytes[3]));
        header_len = 4u;
    } else if (payload_len == 127u) {
        return std::nullopt; // unexpected for Close in these tests
    }

    if (frame_bytes.size() < header_len + payload_len || payload_len < 2u) {
        return std::nullopt;
    }
    const auto hi = static_cast<std::uint8_t>(frame_bytes[header_len]);
    const auto lo = static_cast<std::uint8_t>(frame_bytes[header_len + 1u]);
    return static_cast<std::uint16_t>((hi << 8u) | lo);
}

} // namespace qb::http::test

#endif // QBM_HTTP_TESTS_SHARED_WS_LOOPBACK_H

/**
 * @file qbm/http/tests/shared/http2_planned_peer.h
 * @brief A raw HTTP/2 server over TLS, on its own thread, that plays a plan frame by frame against the module's client:
 *        what crosses the client's own reset, and the frames the client closes a connection for (Huly QB-1270).
 *
 * The module's server never sends a frame on a stream its client reset, nor a frame on stream 0: this peer does, at the
 * moment the plan says, within the windows the client grants, and records what the client answers -- its resets and
 * its first GOAWAY. Used by system/http2/http2-client.cpp and, for the body past MAX_BODY_SIZE (100 MiB on the wire),
 * by system/http2/http2-client-huge-body.cpp, a binary of its own labelled huge-body.
 *
 * Header-only, test-only. Contains no TEST()/main().
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#ifndef QBM_HTTP_TESTS_SHARED_HTTP2_PLANNED_PEER_H
#define QBM_HTTP_TESTS_SHARED_HTTP2_PLANNED_PEER_H

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <qb/io/tcp/ssl/listener.h>
#include <qb/io/tcp/ssl/socket.h>

#include <qbm/http/1.1/protocol/base.h>
#include <qbm/http/2/protocol/hpack.h>

#include "./ssl_test_resource.h"

namespace qb::http::test {

/// One-connection TLS + HTTP/2 server peer on its own thread, written frame by frame: it negotiates ALPN h2, sends empty
/// SETTINGS and the ACK of the client's, waits for the client's requests, then plays its plan -- within the windows the
/// client grants, 65535 octets for the connection and for each stream to begin with, raised by the client's
/// WINDOW_UPDATEs. Every wait is a poll() of its socket, bounded; it records the resets the client sends and the first
/// GOAWAY, and reads until the client ends the connection or the test releases it.
class Http2PlannedPeer {
public:
    enum class Plan {
        /// Stream 1: a 200 whose body passes MAX_BODY_SIZE (100 MiB), streamed as the windows allow. The frame that
        /// passes it, a DATA and the trailers behind it -- which index `x-crossed: one` in the HPACK table -- are written
        /// at once, so they are in flight when the client resets the stream; then stream 3: a 200 that names
        /// `x-crossed` by its index, body "three".
        body_past_the_limit,
        /// The same with a body that passes its `content-length: 1` at its first DATA: two octets, then the rest.
        body_past_its_content_length,
        /// A HEADERS on stream 5, idle while the client's only request is stream 1.
        headers_on_an_idle_stream,
        /// A DATA on stream 0.
        data_on_stream_zero,
        /// A PING of 7 octets, which the client's frame layer refuses.
        ping_of_seven_octets,
        /// A SETTINGS on stream 1, refused on its header alone (Huly QB-1270): so are the next three.
        settings_on_a_stream,
        /// A PING on stream 1.
        ping_on_a_stream,
        /// A GOAWAY on stream 1.
        goaway_on_a_stream,
        /// The header of a DATA on stream 1 one octet past the client's SETTINGS_MAX_FRAME_SIZE (16384), and no payload: the
        /// client refuses it on its header alone, and nothing of it is left unread when it closes.
        frame_past_max_frame_size,
        /// Stream 1 answered and ended (a 200, END_STREAM), then a DATA on it, while stream 3 waits.
        data_after_the_response_completed,
        /// Stream 1: a 200, then 10000 empty DATA frames without END_STREAM and a PING in one write (the empty-frame flood,
        /// CVE-2019-9518); once the PONG is back, one empty DATA and a PING at a time, until the client's GOAWAY.
        empty_data_flood,
        /// Stream 1: a 200, then 200 chunks of "abc", three empty DATA frames after each, then an empty DATA that ends the
        /// stream: a legitimate stream of chunks.
        empty_data_between_chunks,
    };

    /// @p budget bounds the peer's whole life: every wait ends by then, so a test keeps its own bounds under its binary's.
    explicit Http2PlannedPeer(Plan plan, std::chrono::seconds budget = std::chrono::seconds(60))
        : _plan(plan)
        , _budget(budget) {
        _listener.init(qb::io::ssl::Context::server(qb::http::test::ssl_cert_path(), qb::http::test::ssl_key_path()).alpn({"h2"}));
        if (_listener.listen_v4(0, "127.0.0.1") != 0) {
            return;
        }
        _listener.set_nonblocking(true);
        _port   = _listener.local_endpoint().port();
        _thread = std::thread([this] { run(); });
    }
    ~Http2PlannedPeer() {
        _release = true;
        if (_thread.joinable()) {
            _thread.join();
        }
    }
    Http2PlannedPeer(const Http2PlannedPeer &)            = delete;
    Http2PlannedPeer &operator=(const Http2PlannedPeer &) = delete;

    [[nodiscard]] uint16_t
    port() const noexcept {
        return _port;
    }
    /// The client ended the connection.
    [[nodiscard]] bool
    eof() const noexcept {
        return _eof.load();
    }
    [[nodiscard]] bool
    goaway() const noexcept {
        return _goaway.load();
    }
    /// The error code and the debug data of the first GOAWAY the client sent.
    [[nodiscard]] std::pair<uint32_t, std::string>
    first_goaway() const {
        std::lock_guard lock(_mutex);
        return {_goaway_code, _goaway_debug};
    }
    /// The RST_STREAM frames the client sent, as (stream, error code).
    [[nodiscard]] std::vector<std::pair<uint32_t, uint32_t>>
    resets() const {
        std::lock_guard lock(_mutex);
        return _resets;
    }

private:
    static void
    append_frame(std::vector<uint8_t> &out, uint8_t type, uint8_t flags, uint32_t stream_id, const std::vector<uint8_t> &payload) {
        const auto n = static_cast<uint32_t>(payload.size());
        out.insert(out.end(), {static_cast<uint8_t>(n >> 16), static_cast<uint8_t>(n >> 8), static_cast<uint8_t>(n), type, flags,
                               static_cast<uint8_t>(stream_id >> 24), static_cast<uint8_t>(stream_id >> 16),
                               static_cast<uint8_t>(stream_id >> 8), static_cast<uint8_t>(stream_id)});
        out.insert(out.end(), payload.begin(), payload.end());
    }
    [[nodiscard]] static uint32_t
    be32(const uint8_t *p) noexcept {
        return (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | p[3];
    }
    [[nodiscard]] bool
    over() const noexcept {
        return _release || _eof || std::chrono::steady_clock::now() >= _deadline;
    }
    /// Wait, 20 ms at most, for the socket to be readable (POLLIN) or writable (POLLOUT).
    void
    wait_for(short events) {
        pollfd pfd{};
        pfd.fd     = _sock.native_handle();
        pfd.events = events;
        static_cast<void>(::poll(&pfd, 1, 20));
    }
    /// The client's window for @p stream_id: 65535 until its WINDOW_UPDATEs raise it.
    int64_t &
    window(uint32_t stream_id) {
        return _windows.try_emplace(stream_id, int64_t{65535}).first->second;
    }
    /// Write all of @p bytes; false once the connection is gone or the time is up.
    bool
    send(const std::vector<uint8_t> &bytes) {
        std::size_t off = 0;
        while (off < bytes.size()) {
            if (over()) {
                return false;
            }
            const int n = _sock.write(reinterpret_cast<const char *>(bytes.data() + off), bytes.size() - off);
            if (n < 0) {
                _eof = true;
                return false;
            }
            if (n == 0) {
                wait_for(POLLOUT);
                continue;
            }
            off += static_cast<std::size_t>(n);
        }
        return true;
    }
    /// Read what the client sent, if anything, and take its frames in; false once the connection is gone or the time is up.
    bool
    read_some() {
        if (over()) {
            return false;
        }
        char      buffer[16384];
        const int n = _sock.read(buffer, sizeof(buffer));
        if (n < 0) {
            _eof = true;
            return false;
        }
        if (n == 0) {
            wait_for(POLLIN);
            return true;
        }
        _in.insert(_in.end(), buffer, buffer + n);
        if (!_preface_seen) {
            if (_in.size() < 24) {
                return true;
            }
            _in.erase(_in.begin(), _in.begin() + 24);
            _preface_seen = true;
        }
        std::size_t at = 0;
        while (_in.size() - at >= 9) {
            const uint8_t    *head   = _in.data() + at;
            const std::size_t length = (std::size_t{head[0]} << 16) | (std::size_t{head[1]} << 8) | head[2];
            if (_in.size() - at < 9 + length) {
                break;
            }
            const uint8_t  type = head[3], flags = head[4];
            const uint32_t stream_id = be32(head + 5) & 0x7FFFFFFFu;
            const uint8_t *payload   = head + 9;
            if (type == 0x4 && (flags & 0x1) == 0 && !_answered) {
                std::vector<uint8_t> reply;
                append_frame(reply, 0x4, 0, 0, {});   // our SETTINGS
                append_frame(reply, 0x4, 0x1, 0, {}); // the ACK of the client's
                if (!send(reply)) {
                    return false;
                }
                _answered = true;
            } else if (type == 0x1) {
                _requests.push_back(stream_id);
            } else if (type == 0x8 && length == 4) {
                const auto increment = static_cast<int64_t>(be32(payload) & 0x7FFFFFFFu);
                (stream_id == 0 ? _connection_window : window(stream_id)) += increment;
            } else if (type == 0x3 && length == 4) {
                std::lock_guard lock(_mutex);
                _resets.emplace_back(stream_id, be32(payload));
            } else if (type == 0x6 && (flags & 0x1) != 0) {
                ++_pongs;
            } else if (type == 0x7 && length >= 8 && !_goaway) {
                std::lock_guard lock(_mutex);
                _goaway_code = be32(payload + 4);
                _goaway_debug.assign(payload + 8, payload + length);
                _goaway = true;
            }
            at += 9 + length;
        }
        _in.erase(_in.begin(), _in.begin() + static_cast<std::ptrdiff_t>(at));
        return true;
    }
    /// Read until the windows let @p octets go on @p stream_id (and on the connection); false if they never do.
    bool
    wait_for_window(uint32_t stream_id, std::size_t octets, std::size_t connection_octets) {
        while (window(stream_id) < static_cast<int64_t>(octets) || _connection_window < static_cast<int64_t>(connection_octets)) {
            if (!read_some()) {
                return false;
            }
        }
        return true;
    }

    void
    play_body_past_the_limit() {
        qb::protocol::hpack::Encoder encoder; // the server's: one for the connection
        const auto                   block = [&](const std::vector<qb::protocol::hpack::HeaderField> &fields) {
            std::vector<uint8_t> out;
            static_cast<void>(encoder.encode(fields, out));
            return out;
        };
        std::vector<uint8_t> head;
        append_frame(head, 0x1, 0x4, 1, block({{":status", "200"}})); // END_HEADERS, no content-length
        if (!send(head)) {
            return;
        }
        constexpr std::size_t      frame = 16384;
        const std::vector<uint8_t> chunk(frame, static_cast<uint8_t>('b'));
        std::vector<uint8_t>       bytes;
        append_frame(bytes, 0x0, 0, 1, chunk);
        std::size_t sent = 0;
        while (sent + frame <= qb::http::protocol_limits::MAX_BODY_SIZE) { // the body up to the limit, within the windows
            if (!wait_for_window(1, frame, frame) || !send(bytes)) {
                return;
            }
            window(1) -= static_cast<int64_t>(frame);
            _connection_window -= static_cast<int64_t>(frame);
            sent += frame;
        }
        play_crossing(block, chunk);
    }

    /// Stream 1: a 200 of `content-length: 1`, and a first DATA of two octets that passes it.
    void
    play_body_past_its_content_length() {
        qb::protocol::hpack::Encoder encoder; // the server's: one for the connection
        const auto                   block = [&](const std::vector<qb::protocol::hpack::HeaderField> &fields) {
            std::vector<uint8_t> out;
            static_cast<void>(encoder.encode(fields, out));
            return out;
        };
        std::vector<uint8_t> head;
        append_frame(head, 0x1, 0x4, 1, block({{":status", "200"}, {"content-length", "1"}}));
        if (send(head)) {
            play_crossing(block, {static_cast<uint8_t>('a'), static_cast<uint8_t>('b')});
        }
    }

    /// The frame stream 1 is reset for, what the server sends behind it and the answer to stream 3, in one write: all of
    /// it is on its way when the client resets stream 1.
    template <typename Block>
    void
    play_crossing(const Block &block, const std::vector<uint8_t> &crossing) {
        constexpr std::size_t behind = 8192;
        const std::size_t     total  = crossing.size() + behind + 5;
        if (!wait_for_window(1, crossing.size() + behind, total) || !wait_for_window(3, 5, total)) {
            return;
        }
        std::vector<uint8_t> burst;
        append_frame(burst, 0x0, 0, 1, crossing);                                                // the client resets stream 1
        append_frame(burst, 0x0, 0, 1, std::vector<uint8_t>(behind, static_cast<uint8_t>('b'))); // in flight
        append_frame(burst, 0x1, 0x5, 1, block({{"x-crossed", "one"}}));                         // its trailers: END_STREAM | END_HEADERS
        append_frame(burst, 0x1, 0x4, 3, block({{":status", "200"}, {"x-crossed", "one"}}));     // the other request
        append_frame(burst, 0x0, 0x1, 3, {'t', 'h', 'r', 'e', 'e'});
        static_cast<void>(send(burst));
    }

    /// Stream 1: a 200, then 10000 empty DATA frames and a PING in one write; once the PONG is back, one empty DATA and a
    /// PING at a time until the client's GOAWAY. Each frame the client refuses shares its write with the PING behind it,
    /// so the client leaves nothing of it unread in the kernel, whatever it does with its socket once it has closed.
    void
    play_empty_data_flood() {
        static constexpr std::array<uint8_t, 8> opaque{'q', 'b', '-', '1', '2', '7', '0', 0};
        const std::vector<uint8_t>              ping(opaque.begin(), opaque.end());
        std::vector<uint8_t>                    burst;
        append_frame(burst, 0x1, 0x4, 1, {0x88}); // HEADERS, END_HEADERS, stream 1: `:status: 200`
        for (int i = 0; i < 10000; ++i) {
            append_frame(burst, 0x0, 0, 1, {});
        }
        append_frame(burst, 0x6, 0, 0, ping);
        std::size_t pongs = _pongs;
        if (!send(burst)) {
            return;
        }
        while (!_goaway) {
            while (_pongs == pongs && !_goaway) {
                if (!read_some()) {
                    return;
                }
            }
            pongs = _pongs;
            std::vector<uint8_t> one;
            append_frame(one, 0x0, 0, 1, {});
            append_frame(one, 0x6, 0, 0, ping);
            if (!_goaway && !send(one)) {
                return;
            }
        }
    }

    void
    run() {
        _deadline = std::chrono::steady_clock::now() + _budget;
        while (!_release && std::chrono::steady_clock::now() < _deadline) {
            if (_listener.accept(_sock) == 0 && _sock.is_open()) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (!_sock.is_open()) {
            return;
        }
        _sock.set_nonblocking(true);
        const std::size_t requests = _plan == Plan::body_past_the_limit || _plan == Plan::body_past_its_content_length
                                             || _plan == Plan::data_after_the_response_completed
                                         ? 2u
                                         : 1u;
        while (_requests.size() < requests) {
            if (!read_some()) {
                break;
            }
        }
        if (_requests.size() >= requests) {
            if (_plan == Plan::body_past_the_limit) {
                play_body_past_the_limit();
            } else if (_plan == Plan::body_past_its_content_length) {
                play_body_past_its_content_length();
            } else {
                std::vector<uint8_t> frame;
                if (_plan == Plan::headers_on_an_idle_stream) {
                    append_frame(frame, 0x1, 0x5, 5, {0x88}); // HEADERS, END_STREAM | END_HEADERS, stream 5: `:status: 200`
                } else if (_plan == Plan::data_on_stream_zero) {
                    append_frame(frame, 0x0, 0, 0, {'z', 'e', 'r', 'o'}); // DATA on stream 0
                } else if (_plan == Plan::ping_of_seven_octets) {
                    append_frame(frame, 0x6, 0, 0, {1, 2, 3, 4, 5, 6, 7}); // PING, 7 octets
                } else if (_plan == Plan::settings_on_a_stream) {
                    append_frame(frame, 0x4, 0, 1, {}); // SETTINGS, stream 1
                } else if (_plan == Plan::ping_on_a_stream) {
                    append_frame(frame, 0x6, 0, 1, {1, 2, 3, 4, 5, 6, 7, 8}); // PING, stream 1
                } else if (_plan == Plan::goaway_on_a_stream) {
                    append_frame(frame, 0x7, 0, 1, {0, 0, 0, 0, 0, 0, 0, 0}); // GOAWAY, stream 1
                } else if (_plan == Plan::frame_past_max_frame_size) {
                    frame = {0x00, 0x40, 0x01, 0x0, 0, 0, 0, 0, 1}; // a DATA header declaring 16385 octets, stream 1
                } else if (_plan == Plan::data_after_the_response_completed) {
                    append_frame(frame, 0x1, 0x5, 1, {0x88});             // HEADERS, END_STREAM | END_HEADERS, stream 1: `:status: 200`
                    append_frame(frame, 0x0, 0, 1, {'l', 'a', 't', 'e'}); // a DATA after it
                } else if (_plan == Plan::empty_data_flood) {
                    play_empty_data_flood();
                } else {
                    append_frame(frame, 0x1, 0x4, 1, {0x88});
                    for (int chunk = 0; chunk < 200; ++chunk) {
                        append_frame(frame, 0x0, 0, 1, {'a', 'b', 'c'});
                        for (int empty = 0; empty < 3; ++empty) {
                            append_frame(frame, 0x0, 0, 1, {});
                        }
                    }
                    append_frame(frame, 0x0, 0x1, 1, {});
                }
                if (!frame.empty()) {
                    static_cast<void>(send(frame));
                }
            }
        }
        while (read_some()) {
        }
        _sock.disconnect();
        _sock.close();
    }

    Plan                                       _plan;
    std::chrono::seconds                       _budget;
    qb::io::tcp::ssl::listener                 _listener;
    qb::io::tcp::ssl::socket                   _sock;
    uint16_t                                   _port = 0;
    std::chrono::steady_clock::time_point      _deadline{};
    std::vector<uint8_t>                       _in;
    bool                                       _preface_seen = false;
    bool                                       _answered     = false;
    std::vector<uint32_t>                      _requests;
    int64_t                                    _connection_window = 65535;
    std::map<uint32_t, int64_t>                _windows;
    std::atomic<bool>                          _release{false};
    std::atomic<bool>                          _eof{false};
    std::atomic<bool>                          _goaway{false};
    std::size_t                                _pongs = 0;
    mutable std::mutex                         _mutex;
    uint32_t                                   _goaway_code = 0;
    std::string                                _goaway_debug;
    std::vector<std::pair<uint32_t, uint32_t>> _resets;
    std::thread                                _thread;
};

} // namespace qb::http::test

#endif // QBM_HTTP_TESTS_SHARED_HTTP2_PLANNED_PEER_H

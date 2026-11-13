/**
 * @file qbm/http/tests/shared/http2_raw_client.h
 * @brief A raw HTTP/2 client over TLS for the qbm-http system suites: frames in, frames out, nothing hidden (Huly QB-86).
 *
 * The module's `qb::http2::Client` delivers a response whole, at its END_STREAM, and advertises the windows it wants.
 * The streaming suites need the opposite: to see each DATA frame as it arrives -- before the stream ends -- to choose
 * the initial window the server may fill, to withhold or grant WINDOW_UPDATE, to reset a stream or send a GOAWAY in the
 * middle of a body. This client is that: a blocking-connect TLS socket negotiating ALPN `h2`, the connection preface
 * and a SETTINGS frame of the test's choosing, requests as HPACK-encoded HEADERS, and a frame reader that keeps, per
 * stream, the decoded header blocks, every DATA payload in order, the END_STREAM, a RST_STREAM's code and a trailer
 * block. It answers SETTINGS with an ACK and PING with a PONG, counts the PONGs, the SETTINGS ACKs and the resets it
 * reads -- it can solicit them by the thousand in one write (Huly QB-1270) -- and ignores the rest. No padding is
 * expected from the server (it sends none).
 *
 * Header-only, test-only. Contains no TEST()/main().
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#ifndef QBM_HTTP_TESTS_SHARED_HTTP2_RAW_CLIENT_H
#define QBM_HTTP_TESTS_SHARED_HTTP2_RAW_CLIENT_H

#include <chrono>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <cerrno>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>

#include <qb/io/tcp/ssl/context.h>
#include <qb/io/tcp/ssl/socket.h>

#include <qbm/http/2/protocol/base.h>
#include <qbm/http/2/protocol/hpack.h>

namespace qb::http::test {

/// One HTTP/2 frame as read from the wire.
struct RawFrame {
    std::uint8_t         type      = 0;
    std::uint8_t         flags     = 0;
    std::uint32_t        stream_id = 0;
    std::vector<uint8_t> payload;
};

/// What the client saw of one stream.
struct RawStream {
    std::vector<qb::protocol::hpack::HeaderField> headers;  ///< the first header block (the response head)
    std::vector<qb::protocol::hpack::HeaderField> trailers; ///< a second block, if one came (the trailer section)
    int                                           header_blocks = 0;
    std::vector<std::string>                      data; ///< every DATA payload, in order (empty payloads included)
    std::size_t                                   data_bytes = 0;
    bool                                          end_stream = false;
    bool                                          reset      = false;
    std::uint32_t                                 reset_code = 0;

    [[nodiscard]] std::string
    body() const {
        std::string out;
        for (auto const &piece : data)
            out += piece;
        return out;
    }
    [[nodiscard]] std::string
    header(std::string_view name) const {
        for (auto const &field : headers)
            if (field.name == name)
                return field.value;
        return {};
    }
    [[nodiscard]] std::string
    trailer(std::string_view name) const {
        for (auto const &field : trailers)
            if (field.name == name)
                return field.value;
        return {};
    }
    [[nodiscard]] int
    status() const {
        const auto s = header(":status");
        return s.empty() ? 0 : std::atoi(s.c_str());
    }
};

class Http2RawClient {
public:
    static constexpr std::uint8_t  DATA = 0x0, HEADERS = 0x1, RST_STREAM = 0x3, SETTINGS = 0x4, PING = 0x6, GOAWAY = 0x7, WINDOW_UPDATE = 0x8,
                                   CONTINUATION = 0x9;
    static constexpr std::uint8_t  END_STREAM = 0x1, ACK = 0x1, END_HEADERS = 0x4;
    static constexpr std::uint16_t SETTINGS_INITIAL_WINDOW_SIZE = 0x4, SETTINGS_MAX_FRAME_SIZE = 0x5, SETTINGS_MAX_CONCURRENT_STREAMS = 0x3;

    std::map<std::uint32_t, RawStream> streams;
    std::vector<RawFrame>              frames;                     ///< every frame read, in order
    bool                               eof                = false; ///< the connection is over (read -1)
    bool                               settings_acked     = false; ///< the server acknowledged our SETTINGS
    std::uint32_t                      goaway_last_stream = 0;
    bool                               goaway_seen        = false;
    std::uint32_t                      goaway_code        = 0;
    std::string                        goaway_debug;         ///< the debug data of the last GOAWAY read (Huly QB-1270)
    std::size_t                        pongs         = 0;    ///< the PING frames with ACK read (Huly QB-1270)
    std::size_t                        settings_acks = 0;    ///< the SETTINGS frames with ACK read, ours included
    std::size_t                        resets        = 0;    ///< the RST_STREAM frames read
    bool                               keep_frames   = true; ///< false: `frames` stays empty (a flood's replies are counted)
    /// How long one write may take before it gives up. A client that floods a server sets it far past what a loaded
    /// host can stall for: its writes then stop only when the connection is broken.
    std::chrono::milliseconds write_budget = std::chrono::seconds(2);

    /// SCRATCH (lot T7-H2MAC): what the first failing write and the read that ended the connection met.
    struct h2mac_failure {
        bool                                  seen      = false;
        bool                                  timed_out = false; ///< the write's budget ran out (no error)
        int                                   ret       = 0;
        int                                   qb_errno  = 0;    ///< qb::io::socket::get_last_errno() right after the call
        int                                   raw_errno = 0;    ///< errno right after the call
        std::string                           ssl_state;        ///< SSL_state_string_long()
        int                                   ssl_shutdown = 0; ///< SSL_get_shutdown()
        std::string                           ssl_error;        ///< ERR_error_string_n(ERR_peek_last_error())
        std::size_t                           bytes = 0;        ///< the bytes written (or read) before it
        std::chrono::steady_clock::time_point at{};
    };
    h2mac_failure             h2mac_write_failure, h2mac_read_failure;
    std::size_t               h2mac_bytes_written = 0, h2mac_bytes_read = 0, h2mac_frames_read = 0, h2mac_zero_writes = 0;
    std::vector<std::uint8_t> h2mac_last_types; ///< the types of the last frames read, oldest first (16 at most)
    [[nodiscard]] int
    h2mac_sockopt(int name) const {
        int       value = -1;
        socklen_t len   = sizeof value;
        if (::getsockopt(static_cast<int>(_sock.native_handle()), SOL_SOCKET, name, &value, &len) != 0)
            return -errno;
        return value;
    }

private:
    void
    h2mac_fill(h2mac_failure &f, int ret, std::size_t bytes) {
        const int raw = errno;
        f.seen        = true;
        f.ret         = ret;
        f.qb_errno    = qb::io::socket::get_last_errno();
        f.raw_errno   = raw;
        if (SSL *ssl = _sock.ssl_handle()) {
            if (const char *s = SSL_state_string_long(ssl))
                f.ssl_state = s;
            f.ssl_shutdown = SSL_get_shutdown(ssl);
        }
        char buf[256] = {0};
        if (const unsigned long e = ERR_peek_last_error(); e != 0) {
            ERR_error_string_n(e, buf, sizeof buf);
            f.ssl_error = buf;
        }
        f.bytes = bytes;
        f.at    = std::chrono::steady_clock::now();
    }

public:
    /// Connect over TLS (the self-signed certificate accepted), ALPN h2, then the preface and our SETTINGS. `settings`
    /// are id/value pairs (an initial window size, say). `false` when the connection or the ALPN failed.
    bool
    connect(std::uint16_t port, std::vector<std::pair<std::uint16_t, std::uint32_t>> const &settings = {}) {
        _sock = qb::io::tcp::ssl::socket{qb::io::ssl::Context::client().alpn({"h2"})};
        _sock.set_insecure();
        if (_sock.connect_v4("127.0.0.1", port) != 0)
            return false;
        if (_sock.get_alpn_selected_protocol() != "h2")
            return false;
        if (_sock.set_nonblocking(true) != 0)
            return false;
        std::vector<uint8_t> out(HTTP2_CONNECTION_PREFACE.begin(), HTTP2_CONNECTION_PREFACE.end());
        std::vector<uint8_t> payload;
        for (auto const &[id, value] : settings) {
            payload.push_back(static_cast<uint8_t>(id >> 8));
            payload.push_back(static_cast<uint8_t>(id));
            payload.push_back(static_cast<uint8_t>(value >> 24));
            payload.push_back(static_cast<uint8_t>(value >> 16));
            payload.push_back(static_cast<uint8_t>(value >> 8));
            payload.push_back(static_cast<uint8_t>(value));
        }
        append_frame(out, SETTINGS, 0, 0, payload);
        return write_all(out);
    }

    /// Send a request as one HEADERS frame with END_STREAM (no body); returns its stream id (1, 3, 5, ...).
    std::uint32_t
    request(std::string_view path, std::string_view method = "GET", std::vector<std::pair<std::string, std::string>> const &extra = {}) {
        const std::uint32_t stream_id = _next_stream_id;
        _next_stream_id += 2;
        std::vector<qb::protocol::hpack::HeaderField> fields = {
            {":method", std::string(method)}, {":scheme", "https"}, {":authority", "localhost"}, {":path", std::string(path)}
        };
        for (auto const &[name, value] : extra)
            fields.emplace_back(name, value);
        std::vector<uint8_t> block;
        if (!_encoder.encode(fields, block))
            return 0;
        std::vector<uint8_t> out;
        append_frame(out, HEADERS, END_STREAM | END_HEADERS, stream_id, block);
        return write_all(out) ? stream_id : 0;
    }

    /// What `solicit()` sends: each frame draws one reply of the server -- a PONG, a SETTINGS ACK, or the RST_STREAM
    /// that answers a frame on a closed stream.
    enum class soliciting { pings, settings, data_on_a_closed_stream };

    /// `count` PING frames, empty SETTINGS frames, or DATA frames of one octet on `closed_stream`, in ONE write (Huly
    /// QB-1270) -- an octet, so that they meet the reset guards, not the bucket of the frames that make no progress an
    /// empty DATA takes a token of. `false` when the write did not finish within `write_budget`, or the connection is
    /// broken.
    bool
    solicit(int count, soliciting what = soliciting::pings, std::uint32_t closed_stream = 0) {
        std::vector<uint8_t> out;
        out.reserve(static_cast<std::size_t>(count) * 17u);
        for (int i = 0; i < count; ++i) {
            if (what == soliciting::settings)
                append_frame(out, SETTINGS, 0, 0, {});
            else if (what == soliciting::data_on_a_closed_stream)
                append_frame(out, DATA, 0, closed_stream, {'x'});
            else
                append_frame(out, PING, 0, 0, {0x51, 0x42, 0x31, 0x32, 0x37, 0x30, 0x00, 0x00});
        }
        return write_all(out);
    }

    bool
    window_update(std::uint32_t stream_id, std::uint32_t increment) {
        std::vector<uint8_t> out;
        append_frame(out, WINDOW_UPDATE, 0, stream_id,
                     {static_cast<uint8_t>(increment >> 24), static_cast<uint8_t>(increment >> 16), static_cast<uint8_t>(increment >> 8),
                      static_cast<uint8_t>(increment)});
        return write_all(out);
    }

    /// Several WINDOW_UPDATEs in ONE write, so that the server reads them in one pass (Huly QB-86): each pair is a
    /// stream id and its increment.
    bool
    window_updates(std::vector<std::pair<std::uint32_t, std::uint32_t>> const &updates) {
        std::vector<uint8_t> out;
        for (auto const &[stream_id, increment] : updates)
            append_frame(out, WINDOW_UPDATE, 0, stream_id,
                         {static_cast<uint8_t>(increment >> 24), static_cast<uint8_t>(increment >> 16), static_cast<uint8_t>(increment >> 8),
                          static_cast<uint8_t>(increment)});
        return write_all(out);
    }

    /// Any frame, as given: a frame the server must refuse, say (Huly QB-1270). `false` when the write did not finish.
    bool
    frame(std::uint8_t type, std::uint8_t flags, std::uint32_t stream_id, std::vector<uint8_t> const &payload) {
        std::vector<uint8_t> out;
        append_frame(out, type, flags, stream_id, payload);
        return write_all(out);
    }

    /// The 9 octets of a frame header declaring `length` octets of payload, and no payload: a frame the server refuses on
    /// its header alone, with nothing of it left unread when the server closes (Huly QB-1270).
    bool
    frame_header(std::uint8_t type, std::uint8_t flags, std::uint32_t stream_id, std::uint32_t length) {
        const std::vector<uint8_t> out{
            static_cast<uint8_t>(length >> 16),
            static_cast<uint8_t>(length >> 8),
            static_cast<uint8_t>(length),
            type,
            flags,
            static_cast<uint8_t>((stream_id >> 24) & 0x7F),
            static_cast<uint8_t>(stream_id >> 16),
            static_cast<uint8_t>(stream_id >> 8),
            static_cast<uint8_t>(stream_id)
        };
        return write_all(out);
    }

    bool
    rst_stream(std::uint32_t stream_id, std::uint32_t code) {
        std::vector<uint8_t> out;
        append_frame(
            out, RST_STREAM, 0, stream_id,
            {static_cast<uint8_t>(code >> 24), static_cast<uint8_t>(code >> 16), static_cast<uint8_t>(code >> 8), static_cast<uint8_t>(code)});
        return write_all(out);
    }

    bool
    goaway(std::uint32_t last_stream_id, std::uint32_t code) {
        std::vector<uint8_t> out;
        append_frame(out, GOAWAY, 0, 0,
                     {static_cast<uint8_t>(last_stream_id >> 24), static_cast<uint8_t>(last_stream_id >> 16),
                      static_cast<uint8_t>(last_stream_id >> 8), static_cast<uint8_t>(last_stream_id), static_cast<uint8_t>(code >> 24),
                      static_cast<uint8_t>(code >> 16), static_cast<uint8_t>(code >> 8), static_cast<uint8_t>(code)});
        return write_all(out);
    }

    /// Read frames until `pred()` holds, the connection ends, or `budget` elapses; `pred()` at the end.
    template <typename Pred>
    bool
    read_until(Pred &&pred, std::chrono::milliseconds budget = std::chrono::seconds(5)) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (!pred()) {
            if (eof || std::chrono::steady_clock::now() >= deadline)
                return pred();
            if (!read_some())
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return true;
    }

    /// Read whatever comes for `window`, then stop: what the server sent while the test held something back.
    void
    read_for(std::chrono::milliseconds window) {
        const auto deadline = std::chrono::steady_clock::now() + window;
        while (!eof && std::chrono::steady_clock::now() < deadline) {
            if (!read_some())
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    [[nodiscard]] RawStream const &
    stream(std::uint32_t stream_id) {
        return streams[stream_id];
    }

    void
    close() {
        _sock.disconnect();
    }

private:
    static void
    append_frame(std::vector<uint8_t> &out, std::uint8_t type, std::uint8_t flags, std::uint32_t stream_id,
                 std::vector<uint8_t> const &payload) {
        const auto length = static_cast<std::uint32_t>(payload.size());
        out.push_back(static_cast<uint8_t>(length >> 16));
        out.push_back(static_cast<uint8_t>(length >> 8));
        out.push_back(static_cast<uint8_t>(length));
        out.push_back(type);
        out.push_back(flags);
        out.push_back(static_cast<uint8_t>((stream_id >> 24) & 0x7F));
        out.push_back(static_cast<uint8_t>(stream_id >> 16));
        out.push_back(static_cast<uint8_t>(stream_id >> 8));
        out.push_back(static_cast<uint8_t>(stream_id));
        out.insert(out.end(), payload.begin(), payload.end());
    }

    bool
    write_all(std::vector<uint8_t> const &bytes) {
        const auto  deadline = std::chrono::steady_clock::now() + write_budget;
        std::size_t sent     = 0;
        while (sent < bytes.size()) {
            errno       = 0;
            const int n = _sock.write(reinterpret_cast<char const *>(bytes.data() + sent), bytes.size() - sent);
            if (n > 0) {
                sent += static_cast<std::size_t>(n);
                h2mac_bytes_written += static_cast<std::size_t>(n);
                continue;
            }
            if (n < 0 && !h2mac_write_failure.seen)
                h2mac_fill(h2mac_write_failure, n, h2mac_bytes_written);
            if (n == 0)
                ++h2mac_zero_writes;
            if (n == 0 && std::chrono::steady_clock::now() >= deadline && !h2mac_write_failure.seen) {
                h2mac_fill(h2mac_write_failure, n, h2mac_bytes_written);
                h2mac_write_failure.timed_out = true;
            }
            if (n < 0 || std::chrono::steady_clock::now() >= deadline)
                return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return true;
    }

    /// One read; the frames it completes are dispatched. `true` when bytes came.
    bool
    read_some() {
        char tmp[64 * 1024];
        errno       = 0;
        const int n = _sock.read(tmp, sizeof tmp);
        if (n < 0) {
            if (!h2mac_read_failure.seen)
                h2mac_fill(h2mac_read_failure, n, h2mac_bytes_read);
            eof = true; // the TLS socket reports the end of the connection as -1, and "nothing yet" as 0
            return false;
        }
        if (n == 0)
            return false;
        h2mac_bytes_read += static_cast<std::size_t>(n);
        _in.insert(_in.end(), tmp, tmp + n);
        std::size_t at = 0; // one erase a read, not one a frame: a read of a flood's replies holds thousands of frames
        while (_in.size() - at >= 9) {
            const std::uint8_t *head   = _in.data() + at;
            const std::size_t   length = (std::size_t{head[0]} << 16) | (std::size_t{head[1]} << 8) | head[2];
            if (_in.size() - at < 9 + length)
                break;
            RawFrame f;
            f.type  = head[3];
            f.flags = head[4];
            f.stream_id =
                ((std::uint32_t{head[5]} << 24) | (std::uint32_t{head[6]} << 16) | (std::uint32_t{head[7]} << 8) | head[8]) & 0x7FFFFFFFu;
            f.payload.assign(head + 9, head + 9 + length);
            at += 9 + length;
            ++h2mac_frames_read;
            if (h2mac_last_types.size() == 16)
                h2mac_last_types.erase(h2mac_last_types.begin());
            h2mac_last_types.push_back(f.type);
            dispatch(f);
            if (keep_frames)
                frames.push_back(std::move(f));
        }
        _in.erase(_in.begin(), _in.begin() + static_cast<std::ptrdiff_t>(at));
        return true;
    }

    void
    dispatch(RawFrame const &f) {
        switch (f.type) {
            case SETTINGS:
                if (f.flags & ACK) {
                    settings_acked = true;
                    ++settings_acks;
                } else {
                    std::vector<uint8_t> out;
                    append_frame(out, SETTINGS, ACK, 0, {});
                    (void) write_all(out);
                }
                break;
            case PING:
                if (f.flags & ACK) {
                    ++pongs;
                } else {
                    std::vector<uint8_t> out;
                    append_frame(out, PING, ACK, 0, f.payload);
                    (void) write_all(out);
                }
                break;
            case GOAWAY:
                goaway_seen = true;
                if (f.payload.size() >= 8) {
                    goaway_last_stream = ((std::uint32_t{f.payload[0]} << 24) | (std::uint32_t{f.payload[1]} << 16)
                                          | (std::uint32_t{f.payload[2]} << 8) | f.payload[3])
                                         & 0x7FFFFFFFu;
                    goaway_code = (std::uint32_t{f.payload[4]} << 24) | (std::uint32_t{f.payload[5]} << 16) | (std::uint32_t{f.payload[6]} << 8)
                                  | f.payload[7];
                    goaway_debug.assign(f.payload.begin() + 8, f.payload.end());
                }
                break;
            case DATA: {
                auto &s = streams[f.stream_id];
                s.data.emplace_back(f.payload.begin(), f.payload.end());
                s.data_bytes += f.payload.size();
                if (f.flags & END_STREAM)
                    s.end_stream = true;
                break;
            }
            case HEADERS:
            case CONTINUATION: {
                auto &s = streams[f.stream_id];
                if (f.type == HEADERS) {
                    _block.clear();
                    _block_stream     = f.stream_id;
                    _block_end_stream = (f.flags & END_STREAM) != 0;
                }
                _block.insert(_block.end(), f.payload.begin(), f.payload.end());
                if (f.flags & END_HEADERS) {
                    std::vector<qb::protocol::hpack::HeaderField> fields;
                    bool                                          incomplete = false;
                    (void) _decoder.decode(_block, fields, incomplete);
                    if (s.header_blocks == 0)
                        s.headers = std::move(fields);
                    else
                        s.trailers = std::move(fields);
                    ++s.header_blocks;
                    if (_block_end_stream)
                        s.end_stream = true;
                }
                break;
            }
            case RST_STREAM: {
                ++resets;
                auto &s = streams[f.stream_id];
                s.reset = true;
                if (f.payload.size() >= 4)
                    s.reset_code = (std::uint32_t{f.payload[0]} << 24) | (std::uint32_t{f.payload[1]} << 16)
                                   | (std::uint32_t{f.payload[2]} << 8) | f.payload[3];
                break;
            }
            default:
                break;
        }
    }

    qb::io::tcp::ssl::socket     _sock;
    std::vector<uint8_t>         _in;
    std::vector<uint8_t>         _block;
    std::uint32_t                _block_stream     = 0;
    bool                         _block_end_stream = false;
    std::uint32_t                _next_stream_id   = 1;
    qb::protocol::hpack::Encoder _encoder;
    qb::protocol::hpack::Decoder _decoder;
};

} // namespace qb::http::test

#endif // QBM_HTTP_TESTS_SHARED_HTTP2_RAW_CLIENT_H

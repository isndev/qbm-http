/**
 * @file qbm/http/tests/system/http2/http2-close-after-peer.cpp
 * @brief How an HTTP/2 connection ends when this side ends it, over real TLS sockets: its descriptor goes to the loop of
 *        its thread, which closes it after the peer (Huly QB-1270).
 *
 * A connection an io object ended itself leaves the object for the loop of its thread, which shuts the sending side
 * down, reads and drops what the peer still sends, and closes the descriptor on the peer's EOF, a socket error,
 * `linger()` or `closing_socket_byte_budget()` octets dropped; a server session takes that path when everything it had
 * queued was written. `qb::io::async::detail::closing_sockets()` counts the sockets a loop is closing so: this file reads
 * it on the loop's own thread -- the test's for the client, the server's through a probe sampled on its thread.
 *
 *   - the client (`qb::http2::Client`) ends the connection -- an intentional `disconnect()`, a connection error it
 *     detects -- and a raw TLS server then writes without reading: its writes fail within the byte budget, and on
 *     Linux it then reads the client's GOAWAY. The client kept the descriptor half-closed and read nothing: the server
 *     blocked once the socket buffers were full, for as long as the client lived;
 *   - the server's error GOAWAY (PROTOCOL_ERROR) to a client that was still sending: the client reads it, then EOF. The
 *     session closed the socket with the client's bytes unread, a reset, and on Windows the client read no GOAWAY. The
 *     session is released at once, its descriptor on the loop while the client keeps its end open and closed when it
 *     closes; a client that never reads is refused within the byte budget, not held for `linger()`;
 *   - not every session takes that path: one that ends with output still queued -- a slow reader behind a large
 *     response -- is closed with the session, and the streams of a connection are cancelled when its GOAWAY is sent.
 *
 * Each case runs on connections of its own and leaves nothing behind: no socket on a loop, every thread joined.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "../../shared/http2_raw_client.h"
#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

#include <qb/io/async/lingering_close.h>
#include <qb/io/tcp/ssl/listener.h>
#include <qb/io/tcp/ssl/socket.h>
#include <qbm/http/2/client.h>
#include <qbm/http/http.h>

using namespace std::chrono_literals;
using qb::http::test::Http2RawClient;
using qb::http::test::ServerThread;

namespace http2_close_after_peer_test {

constexpr std::uint8_t  kData = 0x0, kHeaders = 0x1, kSettings = 0x4, kPing = 0x6, kGoaway = 0x7;
constexpr std::uint8_t  kAck = 0x1, kEndStream = 0x1, kEndHeaders = 0x4;
constexpr std::uint32_t kNoError = 0x0, kProtocolError = 0x1;

/// The most a peer that writes into a connection this side ended may have handed its socket before its writes fail: the
/// byte budget, and what the two socket buffers hold besides (10 MiB with Linux's default limits).
constexpr std::size_t kAcceptedBound = std::size_t{64} << 20;

[[nodiscard]] std::int64_t
now_ns() noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

[[nodiscard]] std::int64_t
ms(std::int64_t ns) noexcept {
    return ns / 1000000;
}

[[nodiscard]] std::uint32_t
be32(std::uint8_t const *p) noexcept {
    return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) | (std::uint32_t{p[2]} << 8) | std::uint32_t{p[3]};
}

void
append_frame(std::vector<std::uint8_t> &out, std::uint8_t type, std::uint8_t flags, std::uint32_t stream_id,
             std::vector<std::uint8_t> const &payload) {
    const auto length = static_cast<std::uint32_t>(payload.size());
    out.insert(out.end(), {static_cast<std::uint8_t>(length >> 16), static_cast<std::uint8_t>(length >> 8), static_cast<std::uint8_t>(length),
                           type, flags, static_cast<std::uint8_t>((stream_id >> 24) & 0x7F), static_cast<std::uint8_t>(stream_id >> 16),
                           static_cast<std::uint8_t>(stream_id >> 8), static_cast<std::uint8_t>(stream_id)});
    out.insert(out.end(), payload.begin(), payload.end());
}

/// The complete frames of @p in from @p at, each given to @p each(type, flags, stream id, payload, length); the offset
/// of the first frame not complete yet.
template <typename Each>
std::size_t
parse_frames(std::vector<std::uint8_t> const &in, std::size_t at, Each &&each) {
    while (in.size() - at >= 9) {
        std::uint8_t const *head   = in.data() + at;
        const std::size_t   length = (std::size_t{head[0]} << 16) | (std::size_t{head[1]} << 8) | head[2];
        if (in.size() - at < 9 + length)
            break;
        each(head[3], head[4], be32(head + 5) & 0x7FFFFFFFu, head + 9, length);
        at += 9 + length;
    }
    return at;
}

/// Waits, sleeping, until @p pred holds or @p budget elapses: what the test's thread does while another thread works.
template <typename Pred>
bool
wait_until(Pred &&pred, std::chrono::milliseconds budget) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= deadline)
            return pred();
        std::this_thread::sleep_for(1ms);
    }
    return true;
}

/// Runs the test thread's loop -- the client's, and the loop that closes its sockets -- until @p pred holds or @p budget
/// elapses. Unlike ServerThread::pump_until it fails nothing: the caller's assertion names what did not happen.
template <typename Pred>
bool
pump_until(Pred &&pred, std::chrono::milliseconds budget) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= deadline)
            return pred();
        if (qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT) == 0)
            std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
    return true;
}

// ===========================================================================================================================
// The server: a session that ends its own connection, observed on the server's thread.
// ===========================================================================================================================

/// What the server's thread saw, for the test's thread. One per case: each case starts a server of its own.
struct ServerProbe {
    std::atomic<int>          releases{0};            ///< sessions released (the server's `disconnected()`)
    std::atomic<std::int64_t> released_at{0};         ///< when the first was, steady clock, ns
    std::atomic<int>          closing_at_release{-1}; ///< the loop's closing sockets then: the session's descriptor among them or not
    std::atomic<int>          closing_now{0};         ///< the loop's closing sockets, sampled every millisecond on its thread
    std::atomic<int>          closing_max{0};
    std::atomic<std::int64_t> session_linger{-1}; ///< the session's linger(), ns
    std::atomic<bool>         queued{false};      ///< `/large` answered: its response is in the session's output
    std::atomic<bool>         holding{false};     ///< `/hold` holds the context of a stream under way
    std::atomic<std::int64_t> cancelled_at{0};    ///< when that context was seen cancelled, steady clock, ns
    std::atomic<bool>         drop_held{false};   ///< the test is done with the held context: the server's thread drops it
};

class CloseServer;

class CloseSession : public qb::http2::use<CloseSession>::session<CloseServer> {
public:
    explicit CloseSession(CloseServer &server);
};

/// `/served` answers at once, `/large` answers 64 MiB, `/hold` never answers: its context is held until it is cancelled.
class CloseServer : public qb::http2::use<CloseServer>::server<CloseSession> {
    using base = qb::http2::use<CloseServer>::server<CloseSession>;

public:
    explicit CloseServer(ServerProbe &probe)
        : _probe(probe) {
        router().get("/served", [](auto ctx) {
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });
        router().get("/large", [this](auto ctx) {
            ctx->text(std::string(std::size_t{64} << 20, 'b'));
            _probe.queued = true;
        });
        router().get("/hold", [this](auto ctx) {
            _held          = ctx;
            _probe.holding = true;
            watch_held();
        });
        router().compile();
    }

    [[nodiscard]] ServerProbe &
    probe() noexcept {
        return _probe;
    }

    /// Session hook: a session is released. What the loop is closing then says whether its descriptor went there.
    void
    disconnected(qb::uuid ident) {
        const auto closing = static_cast<int>(qb::io::async::detail::closing_sockets());
        if (_probe.releases.fetch_add(1) == 0) {
            _probe.closing_at_release = closing;
            _probe.released_at        = now_ns();
        }
        base::disconnected(ident);
    }

    /// The loop's closing sockets, sampled every millisecond on this thread for the life of the server's loop.
    void
    sample_closing() {
        qb::io::async::callback(
            [this] {
                const auto closing = static_cast<int>(qb::io::async::detail::closing_sockets());
                _probe.closing_now = closing;
                if (closing > _probe.closing_max.load())
                    _probe.closing_max = closing;
                sample_closing();
            },
            1ms);
    }

private:
    /// Every 5 ms on this thread: the held context, until it is cancelled or the test drops it.
    void
    watch_held() {
        qb::io::async::callback(
            [this] {
                if (!_held)
                    return;
                if (_held->is_cancelled() || _probe.drop_held) {
                    if (_held->is_cancelled())
                        _probe.cancelled_at = now_ns();
                    _held.reset();
                    _probe.holding = false;
                    return;
                }
                watch_held();
            },
            5ms);
    }

    ServerProbe                                     &_probe;
    std::shared_ptr<qb::http::Context<CloseSession>> _held; ///< this thread's only
};

CloseSession::CloseSession(CloseServer &server)
    : session(server) {
    server.probe().session_linger = linger().count();
}

class Http2ServerCloseAfterPeerTest : public ::testing::Test {
protected:
    ServerProbe                                probe;
    std::unique_ptr<ServerThread<CloseServer>> server;
    std::uint16_t                              port{0};

    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available()) << "Missing TLS test certificates (" << qb::http::test::ssl_cert_path() << ")";
        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();
        server                 = std::make_unique<ServerThread<CloseServer>>([this] { return std::make_unique<CloseServer>(probe); },
                                                                             [cert, key](CloseServer &srv) -> bool {
                                                                 srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2"}));
                                                                 if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                                                                     return false;
                                                                 srv.start();
                                                                 srv.sample_closing();
                                                                 return true;
                                                                             });
        ASSERT_TRUE(server->ready());
        port = server->port();
        ASSERT_NE(port, 0);
    }

    void
    TearDown() override {
        probe.drop_held = true;
        static_cast<void>(wait_until([&] { return !probe.holding.load(); }, 5s)); // dropped on the thread it lives on
        server.reset();
    }

    /// The session's linger(), the bound of its descriptor's close after the peer.
    [[nodiscard]] std::chrono::nanoseconds
    session_linger() const {
        return std::chrono::nanoseconds(probe.session_linger.load());
    }

    /// A connection that served a request: the raw client's preface and SETTINGS, ours acknowledged, `/served` answered.
    static void
    serving(Http2RawClient &client, std::uint16_t port) {
        ASSERT_TRUE(client.connect(port));
        ASSERT_TRUE(client.read_until([&] { return client.settings_acked; })) << "the server never acknowledged the SETTINGS";
        const auto served = client.request("/served");
        ASSERT_NE(served, 0u);
        ASSERT_TRUE(client.read_until([&] { return client.stream(served).end_stream; })) << "the connection does not serve";
    }

    /// A HEADERS on stream 0, a connection error: the server answers GOAWAY(PROTOCOL_ERROR) and ends the connection.
    static void
    connection_error(Http2RawClient &client) {
        ASSERT_TRUE(client.frame(kHeaders, kEndStream | kEndHeaders, 0, {0x88}));
    }

    /// PING frames behind the connection error, which the server will never read: as many as the socket takes within
    /// 300 ms, 256 KiB at most. The client was still sending when the server ended the connection.
    static std::size_t
    still_sending(Http2RawClient &client) {
        client.write_budget = 300ms;
        std::size_t pushed  = 0;
        while (pushed < std::size_t{256} << 10 && client.solicit(16))
            pushed += 16 * 17;
        client.write_budget = 2s;
        return pushed;
    }

    /// The server's loop closes no socket after its peer any more.
    [[nodiscard]] bool
    loop_closes_nothing(std::chrono::milliseconds budget = 5s) const {
        return wait_until([&] { return probe.closing_now.load() == 0; }, budget);
    }

    [[nodiscard]] static std::size_t
    goaways(Http2RawClient const &client) {
        return static_cast<std::size_t>(
            std::count_if(client.frames.begin(), client.frames.end(), [](qb::http::test::RawFrame const &f) { return f.type == kGoaway; }));
    }
};

// ===========================================================================================================================
// The client: a raw TLS server it ends a connection with.
// ===========================================================================================================================

/// One-connection TLS + HTTP/2 server peer on its own thread (non-blocking sockets, polled, every wait bounded). It
/// negotiates ALPN h2, answers the client's SETTINGS and waits for the ACK of its own, then makes the client end the
/// connection as its plan says -- or lets the test do it -- and from then on READS NOTHING: what the client sends after
/// it, its GOAWAY included, waits in the socket, and the writes that follow meet the socket (a TLS layer that has read
/// the end of the connection fails every write itself). On the test's word it writes DATA frames without reading until
/// a write fails, its cap or its window, then reads what is left; or it closes.
class ClosingPeer {
public:
    enum class provoke {
        nothing,             ///< the test ends the connection: `client->disconnect()`
        idle_stream_headers, ///< a HEADERS on stream 5, idle while the client's request is stream 1: GOAWAY(PROTOCOL_ERROR)
        empty_data_flood,    ///< a 200, then empty DATA frames, 10000 at once and 1000 a round trip: GOAWAY(ENHANCE_YOUR_CALM)
    };

    /// How long the writes go on before the peer gives up on a client that neither reads nor fails them.
    static constexpr std::chrono::seconds write_window{10};
    /// What the writes stop at: past kAcceptedBound, so that a client that reads for ever is caught by the bound.
    static constexpr std::size_t write_cap = std::size_t{128} << 20;

    explicit ClosingPeer(provoke what)
        : _provoke(what) {
        _listener.init(qb::io::ssl::Context::server(qb::http::test::ssl_cert_path(), qb::http::test::ssl_key_path()).alpn({"h2"}));
        if (_listener.listen_v4(0, "127.0.0.1") != 0)
            return;
        _listener.set_nonblocking(true);
        _port   = _listener.local_endpoint().port();
        _thread = std::thread([this] { run(); });
    }
    ~ClosingPeer() {
        _quit = true;
        if (_thread.joinable())
            _thread.join();
    }
    ClosingPeer(const ClosingPeer &)            = delete;
    ClosingPeer &operator=(const ClosingPeer &) = delete;

    [[nodiscard]] std::uint16_t
    port() const noexcept {
        return _port;
    }
    /// The SETTINGS exchange is over: the client acknowledged ours.
    [[nodiscard]] bool
    ready() const noexcept {
        return _ready.load();
    }
    /// The plan has made the client end the connection: the bad HEADERS is written, or the flood drew the client's GOAWAY.
    [[nodiscard]] bool
    provoked() const noexcept {
        return _provoked.load();
    }
    /// The GOAWAY frames read, and the code of the last.
    [[nodiscard]] std::size_t
    goaways() const noexcept {
        return _goaways.load();
    }
    [[nodiscard]] std::uint32_t
    goaway_code() const noexcept {
        return _goaway_code.load();
    }

    /// Write without reading until a write fails, then read what is left.
    void
    write_until_refused() noexcept {
        _command = command::write;
    }
    /// Close the connection.
    void
    release() noexcept {
        _command = command::release;
    }
    [[nodiscard]] bool
    writing_done() const noexcept {
        return _writing_done.load();
    }
    [[nodiscard]] bool
    write_failed() const noexcept {
        return _write_failed.load();
    }
    /// The octets the socket took once the writes began.
    [[nodiscard]] std::size_t
    written() const noexcept {
        return _written.load();
    }
    [[nodiscard]] bool
    reading_done() const noexcept {
        return _reading_done.load();
    }

private:
    enum class command { none, write, release };

    [[nodiscard]] bool
    over() const noexcept {
        return _quit || std::chrono::steady_clock::now() >= _deadline;
    }
    /// Wait, 20 ms at most, for the socket to be readable (POLLIN) or writable (POLLOUT).
    void
    wait_for(short events) {
        pollfd pfd{};
        pfd.fd     = _sock.native_handle();
        pfd.events = events;
        static_cast<void>(::poll(&pfd, 1, 20));
    }
    /// Write all of @p bytes; false once the connection is gone or the time is up.
    bool
    send(std::vector<std::uint8_t> const &bytes) {
        std::size_t off = 0;
        while (off < bytes.size()) {
            if (over())
                return false;
            const int n = _sock.write(bytes.data() + off, bytes.size() - off);
            if (n < 0)
                return false;
            if (n == 0) {
                wait_for(POLLOUT);
                continue;
            }
            off += static_cast<std::size_t>(n);
        }
        return true;
    }
    /// One read, its complete frames taken in; false once the connection is over or the time is up.
    bool
    read_some() {
        if (over())
            return false;
        char      buffer[16384];
        const int n = _sock.read(buffer, sizeof(buffer));
        if (n < 0)
            return false;
        if (n == 0) {
            wait_for(POLLIN);
            return true;
        }
        _in.insert(_in.end(), buffer, buffer + n);
        if (!_preface_seen) {
            if (_in.size() < 24)
                return true;
            _in.erase(_in.begin(), _in.begin() + 24);
            _preface_seen = true;
        }
        const std::size_t at =
            parse_frames(_in, 0, [&](std::uint8_t type, std::uint8_t flags, std::uint32_t, std::uint8_t const *payload, std::size_t length) {
                take(type, flags, payload, length);
            });
        _in.erase(_in.begin(), _in.begin() + static_cast<std::ptrdiff_t>(at));
        return true;
    }
    void
    take(std::uint8_t type, std::uint8_t flags, std::uint8_t const *payload, std::size_t length) {
        if (type == kSettings && (flags & kAck) != 0) {
            _acked = true;
        } else if (type == kSettings && !_answered) {
            std::vector<std::uint8_t> reply;
            append_frame(reply, kSettings, 0, 0, {});    // ours
            append_frame(reply, kSettings, kAck, 0, {}); // the ACK of the client's
            _answered = send(reply);
        } else if (type == kHeaders) {
            _request_seen = true;
        } else if (type == kPing && (flags & kAck) != 0) {
            ++_pongs;
        } else if (type == kGoaway && length >= 8) {
            _goaway_code = be32(payload + 4);
            ++_goaways;
        }
    }

    /// Stream 1: a 200, then 10000 empty DATA frames and a PING in one write; once the PONG is back, 1000 empty DATA frames
    /// and a PING, and again at each PONG, until the client's GOAWAY -- the shape of http2_planned_peer.h's empty-data
    /// flood. A round is one write the client reads whole: when it cuts the flood, nothing is left unread on its side.
    bool
    flood() {
        static constexpr std::array<std::uint8_t, 8> opaque{'q', 'b', '-', '1', '2', '7', '0', 7};
        const auto                                   round = [&](int empty_frames) {
            std::vector<std::uint8_t> frames;
            if (empty_frames == 10000)
                append_frame(frames, kHeaders, kEndHeaders, 1, {0x88}); // `:status: 200`
            for (int i = 0; i < empty_frames; ++i)
                append_frame(frames, kData, 0, 1, {});
            append_frame(frames, kPing, 0, 0, std::vector<std::uint8_t>(opaque.begin(), opaque.end()));
            return frames;
        };
        std::size_t pongs = _pongs;
        if (!send(round(10000)))
            return false;
        while (_goaways == 0) {
            while (_pongs == pongs && _goaways == 0) {
                if (!read_some())
                    return false;
            }
            pongs = _pongs;
            if (_goaways == 0 && !send(round(1000)))
                return false;
        }
        return true;
    }

    void
    write_until_refused_now() {
        std::vector<std::uint8_t> chunk;
        append_frame(chunk, kData, 0, 1, std::vector<std::uint8_t>(16384, 'x'));
        std::size_t off   = 0;
        const auto  until = std::chrono::steady_clock::now() + write_window;
        while (!_quit && std::chrono::steady_clock::now() < until && _written < write_cap) {
            const int n = _sock.write(chunk.data() + off, chunk.size() - off);
            if (n < 0) {
                _write_failed = true;
                break;
            }
            if (n == 0) {
                wait_for(POLLOUT);
                continue;
            }
            _written += static_cast<std::size_t>(n);
            off = (off + static_cast<std::size_t>(n)) % chunk.size();
        }
        _writing_done = true;
    }

    void
    read_to_end() {
        const auto until = std::chrono::steady_clock::now() + 5s;
        while (std::chrono::steady_clock::now() < until && read_some()) {
        }
        _reading_done = true;
    }

    void
    play() {
        while (!(_answered && _acked)) {
            if (!read_some())
                return;
        }
        _ready = true;
        if (_provoke != provoke::nothing) {
            while (!_request_seen) {
                if (!read_some())
                    return;
            }
        }
        if (_provoke == provoke::idle_stream_headers) {
            std::vector<std::uint8_t> frame;
            append_frame(frame, kHeaders, kEndStream | kEndHeaders, 5, {0x88}); // stream 5: idle, the client's request is 1
            if (!send(frame))
                return;
            _provoked = true;
        } else if (_provoke == provoke::empty_data_flood) {
            if (!flood())
                return;
            _provoked = true;
        }
        while (_command == command::none && !over())
            std::this_thread::sleep_for(1ms);
        if (_command == command::write) {
            write_until_refused_now();
            read_to_end();
        }
    }

    void
    run() {
        _deadline = std::chrono::steady_clock::now() + 60s;
        while (!over()) {
            if (_listener.accept(_sock) == 0 && _sock.is_open())
                break;
            std::this_thread::sleep_for(1ms);
        }
        if (_sock.is_open()) {
            _sock.set_nonblocking(true);
            play();
        }
        _writing_done = true; // a peer that gave up early has nothing more to say
        _reading_done = true;
        _sock.disconnect();
        _sock.close();
    }

    provoke                               _provoke;
    qb::io::tcp::ssl::listener            _listener;
    qb::io::tcp::ssl::socket              _sock;
    std::uint16_t                         _port = 0;
    std::chrono::steady_clock::time_point _deadline{};
    std::vector<std::uint8_t>             _in;
    bool                                  _preface_seen = false;
    bool                                  _answered     = false;
    bool                                  _acked        = false;
    bool                                  _request_seen = false;
    std::size_t                           _pongs        = 0;
    std::atomic<command>                  _command{command::none};
    std::atomic<bool>                     _quit{false};
    std::atomic<bool>                     _ready{false};
    std::atomic<bool>                     _provoked{false};
    std::atomic<std::size_t>              _goaways{0};
    std::atomic<std::uint32_t>            _goaway_code{0};
    std::atomic<bool>                     _writing_done{false};
    std::atomic<bool>                     _write_failed{false};
    std::atomic<std::size_t>              _written{0};
    std::atomic<bool>                     _reading_done{false};
    std::thread                           _thread;
};

class Http2ClientCloseAfterPeerTest : public ::testing::Test {
protected:
    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available()) << "Missing TLS test certificates (" << qb::http::test::ssl_cert_path() << ")";
        qb::io::async::init();
    }

    void
    TearDown() override {
        // Each case asserts that its loop closes nothing any more; a case cut short by a fatal failure leaves nothing to
        // the next one either.
        static_cast<void>(qb::io::async::detail::release_closing_sockets());
    }

    [[nodiscard]] static std::shared_ptr<qb::http2::Client>
    connected_client(std::uint16_t port) {
        auto client = qb::http2::make_client("https://localhost:" + std::to_string(port));
        client->set_verify_peer(false); // self-signed test cert
        client->set_connect_timeout(5s);
        client->set_request_timeout(90s); // a request ends with its response or with the connection, not on its own
        client->disable_auto_reconnect();
        bool connected = false;
        client->connect([&](bool ok, const std::string &) { connected = ok; });
        EXPECT_TRUE(pump_until([&] { return connected; }, 10s)) << "the client did not connect";
        return client;
    }

    [[nodiscard]] static qb::http::Request
    get(const char *path) {
        qb::http::Request request;
        request.method() = qb::http::Method::GET;
        request.uri()    = qb::io::uri(path);
        return request;
    }
};

} // namespace http2_close_after_peer_test

using namespace http2_close_after_peer_test;

// The client ends the connection -- an intentional disconnect(), its GOAWAY(NO_ERROR) first; a HEADERS on an idle
// stream, a connection error it answers with GOAWAY(PROTOCOL_ERROR) -- and the server, which read nothing since, writes
// 16 KiB DATA frames without reading. The client's loop shuts the sending side down and drops what comes, up to the
// byte budget, then closes: the server's writes fail, having handed its socket no more than the budget and what the two
// socket buffers hold. It then reads what the client had sent: on Linux the GOAWAY, then the end. On Windows the
// server's own failed write -- the reset it drew -- may have destroyed what it had received and not read: the GOAWAY is
// asserted on Linux alone. The client kept the descriptor half-closed and read nothing: the server's writes blocked
// once the buffers were full (4.2 MB on Linux, 180 KB on Windows) and never failed for as long as the client lived.
TEST_F(Http2ClientCloseAfterPeerTest, AServerThatWritesWithoutReadingIntoAConnectionTheClientEndedSeesItsWritesFail) {
    struct ending {
        const char          *name;
        ClosingPeer::provoke provoke;
        std::uint32_t        code; // the client's GOAWAY
    };
    // Each way on a connection of its own, and judged on its own: a fatal assertion ends that way, not the test.
    const auto ends = [&](ending const &each) {
        SCOPED_TRACE(each.name);
        ClosingPeer peer(each.provoke);
        ASSERT_NE(peer.port(), 0);
        auto client = connected_client(peer.port());
        ASSERT_TRUE(client->is_connected());
        ASSERT_TRUE(pump_until([&] { return peer.ready(); }, 10s)) << "the SETTINGS exchange did not end";
        if (each.provoke == ClosingPeer::provoke::nothing) {
            client->disconnect();
        } else {
            std::optional<qb::http::Response> response;
            ASSERT_TRUE(client->push_request(get("/pending"), [&](qb::http::Response r) { response = std::move(r); }));
            ASSERT_TRUE(pump_until([&] { return response.has_value(); }, 10s)) << "the client did not end the connection";
            EXPECT_EQ(response->body().as<std::string>(), "GOAWAY sent by client: HEADERS frame received on idle client stream");
        }
        EXPECT_TRUE(pump_until([&] { return !client->transport().is_open(); }, 3s))
            << "the client kept the descriptor of the connection it ended";

        peer.write_until_refused();
        ASSERT_TRUE(pump_until([&] { return peer.writing_done(); }, ClosingPeer::write_window + 20s));
        EXPECT_TRUE(peer.write_failed()) << "the server's writes never failed: its socket took " << peer.written()
                                         << " octets, then nothing more for " << ClosingPeer::write_window.count() << " s";
        EXPECT_LE(peer.written(), kAcceptedBound)
            << "the client's loop read the server past its byte budget (" << qb::io::async::detail::closing_socket_byte_budget() << ")";
        RecordProperty(each.provoke == ClosingPeer::provoke::nothing ? "disconnect_octets_taken" : "connection_error_octets_taken",
                       std::to_string(peer.written()));
        ASSERT_TRUE(pump_until([&] { return peer.reading_done(); }, 10s));
#if defined(__linux__)
        EXPECT_EQ(peer.goaways(), 1u) << "the server did not read the client's GOAWAY after its failed write";
        EXPECT_EQ(peer.goaway_code(), each.code);
#endif
        client.reset();
        EXPECT_EQ(qb::io::async::detail::closing_sockets(), 0u) << "the client's loop still closes a socket";
    };
    ends({"an intentional disconnect()", ClosingPeer::provoke::nothing, kNoError});
    ends({"a connection error the client detects", ClosingPeer::provoke::idle_stream_headers, kProtocolError});
}

// A connection error the server detects (a HEADERS on stream 0) is answered with GOAWAY(PROTOCOL_ERROR). The client had
// more on its way -- PING frames the server will never read -- writes again once the server has released the session,
// and only then reads: the GOAWAY, one, then the end of the connection. The session closed its socket with the client's
// bytes unread: a reset, which on Windows destroyed the GOAWAY the client had received and not read yet -- it read none
// (Linux kept it).
TEST_F(Http2ServerCloseAfterPeerTest, TheErrorGoawayReachesAClientThatWasStillSending) {
    Http2RawClient client;
    ASSERT_NO_FATAL_FAILURE(serving(client, port));
    ASSERT_NO_FATAL_FAILURE(connection_error(client));
    const std::size_t pushed = still_sending(client);
    ASSERT_TRUE(wait_until([&] { return probe.releases.load() > 0; }, 5s)) << "the server did not end the connection";
    // A reset the server's close sent, if it sent one, has arrived -- nothing on the client's side marks it -- and the one
    // a write into a closed socket draws: the client writes again, and waits as long.
    std::this_thread::sleep_for(300ms);
    static_cast<void>(client.solicit(16));
    std::this_thread::sleep_for(300ms);
    EXPECT_TRUE(client.read_until([&] { return client.eof; }, 5s)) << "the server did not end the connection";
    EXPECT_EQ(goaways(client), 1u) << "the server's GOAWAY was lost (the client had pushed " << pushed << " octets behind its error)";
    RecordProperty("octets_pushed_behind_the_error", std::to_string(pushed));
    EXPECT_EQ(client.goaway_code, kProtocolError);
    client.close();
    EXPECT_TRUE(loop_closes_nothing()) << "the server's loop still closes the socket of a client that closed";
}

// The same error GOAWAY to a client still sending: the session is released at once, its descriptor on the server's loop
// -- one closing socket while the client keeps its end open -- and closed when the client closes, before the bound. The
// session closed it at once, the client's bytes unread.
TEST_F(Http2ServerCloseAfterPeerTest, AnErrorGoawayLeavesThroughTheLoopUntilTheClientCloses) {
    Http2RawClient client;
    ASSERT_NO_FATAL_FAILURE(serving(client, port));
    const std::int64_t sent_at = now_ns();
    ASSERT_NO_FATAL_FAILURE(connection_error(client));
    static_cast<void>(still_sending(client));
    ASSERT_TRUE(wait_until([&] { return probe.releases.load() > 0; }, 5s)) << "the server did not end the connection";
    const std::int64_t released_at = probe.released_at.load();
    EXPECT_LT(released_at - sent_at, (session_linger() / 2).count())
        << "the session was released " << ms(released_at - sent_at) << " ms after the error, not at once";
    EXPECT_EQ(probe.closing_at_release.load(), 1) << "the session's descriptor did not go to the loop's closer";
    EXPECT_TRUE(wait_until([&] { return probe.closing_now.load() == 1; }, 1s)) << "no socket on the loop while the client is open";
    ASSERT_TRUE(client.read_until([&] { return client.goaway_seen; })) << "the server's GOAWAY was lost";
    EXPECT_EQ(client.goaway_code, kProtocolError);

    client.close(); // the loop reads the client's EOF and closes the socket
    ASSERT_TRUE(loop_closes_nothing()) << "the client closed and the server's loop kept its socket";
    const std::int64_t closed_at = now_ns();
    EXPECT_LT(closed_at - released_at, session_linger().count())
        << "the socket was closed " << ms(closed_at - released_at) << " ms after the release: at its bound, not when the client closed";
    EXPECT_EQ(probe.closing_max.load(), 1);
    RecordProperty("released_after_ms", std::to_string(ms(released_at - sent_at)));
    RecordProperty("closed_after_release_ms", std::to_string(ms(closed_at - released_at)));
}

// The same error to a client that never reads and keeps writing: the loop drops what it sends up to the byte budget,
// then closes -- its writes fail, long before the session's linger(), and the server took no more than the budget and
// what the socket buffers hold.
TEST_F(Http2ServerCloseAfterPeerTest, AClientThatNeverReadsIsRefusedWithinTheByteBudget) {
    Http2RawClient client;
    ASSERT_NO_FATAL_FAILURE(serving(client, port));
    ASSERT_NO_FATAL_FAILURE(connection_error(client));
    // A write stops when the connection is broken, never because a loaded host is slow: one that stalls this long is
    // not refused, it is held.
    client.write_budget             = 10s;
    constexpr int         per_write = 900; // PING frames of 17 octets: one TLS record a write
    constexpr std::size_t octets    = std::size_t{per_write} * 17;
    const auto            t0        = std::chrono::steady_clock::now();
    std::size_t           taken     = 0;
    bool                  refused   = false;
    while (std::chrono::steady_clock::now() - t0 < 30s && taken < 2 * kAcceptedBound) {
        const auto write_began = std::chrono::steady_clock::now();
        if (!client.solicit(per_write)) {
            refused = std::chrono::steady_clock::now() - write_began < client.write_budget;
            break;
        }
        taken += octets;
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
    EXPECT_TRUE(refused) << "a client that never reads was not refused: " << taken << " octets taken in " << elapsed.count() << " ms";
    EXPECT_LT(elapsed.count(), (std::chrono::duration_cast<std::chrono::milliseconds>(session_linger()) + 3s).count())
        << "the connection of a client that never reads was held " << elapsed.count() << " ms, past the session's linger()";
    EXPECT_LE(taken + octets, kAcceptedBound) << "the server's loop read the client past its byte budget ("
                                              << qb::io::async::detail::closing_socket_byte_budget() << ")";
    RecordProperty("octets_taken", std::to_string(taken));
    RecordProperty("refused_after_ms", std::to_string(elapsed.count()));
    client.close();
    EXPECT_TRUE(loop_closes_nothing()) << "the server's loop still closes the socket of a client that closed";
}

// A client that opened its windows wide asks for 64 MiB and reads nothing: the socket takes what it can, the rest waits
// in the session's output. Then the connection error: its GOAWAY is queued behind the response, and the client reads
// about 1 MiB a second. The session ends the connection without waiting for the reader: released at once, with its
// output, its socket closed with it -- no socket on the loop -- and the client sees the end once it has read what the
// socket had taken.
TEST_F(Http2ServerCloseAfterPeerTest, ASlowReaderBehindALargeResponseDoesNotHoldTheSession) {
    Http2RawClient client;
    client.keep_frames = false; // the response's frames are counted in its stream, not kept twice
    ASSERT_TRUE(client.connect(port, {{Http2RawClient::SETTINGS_INITIAL_WINDOW_SIZE, 0x7FFFFFFFu}}));
    ASSERT_TRUE(client.window_update(0, 0x7FFF0000u)); // the connection's window as wide: the response is queued at once
    ASSERT_TRUE(client.read_until([&] { return client.settings_acked; })) << "the server never acknowledged the SETTINGS";
    const auto large = client.request("/large");
    ASSERT_NE(large, 0u);
    ASSERT_TRUE(wait_until([&] { return probe.queued.load(); }, 10s)) << "the response was not queued";

    const std::int64_t sent_at = now_ns();
    ASSERT_NO_FATAL_FAILURE(connection_error(client));
    // 256 KiB every 250 ms, far below what loopback gives, until the server released the session
    while (probe.releases.load() == 0 && !client.eof && now_ns() - sent_at < std::chrono::nanoseconds(10s).count()) {
        const std::size_t burst = client.stream(large).data_bytes + (std::size_t{256} << 10);
        static_cast<void>(client.read_until([&] { return client.stream(large).data_bytes >= burst; }, 50ms));
        std::this_thread::sleep_for(250ms);
    }
    ASSERT_GT(probe.releases.load(), 0) << "a slow reader held the session of an error GOAWAY";
    const std::int64_t released_at = probe.released_at.load();
    EXPECT_LT(released_at - sent_at, session_linger().count())
        << "the session waited " << ms(released_at - sent_at) << " ms for its slow reader";
    EXPECT_EQ(probe.closing_at_release.load(), 0) << "a session that ended with output still queued gave its descriptor to the loop";
    EXPECT_TRUE(client.read_until([&] { return client.eof; }, 20s)) << "the client never saw the end of the connection";
    EXPECT_LT(client.stream(large).data_bytes, std::size_t{64} << 20) << "the whole response was delivered: nothing was queued";
    EXPECT_EQ(probe.closing_max.load(), 0);
    RecordProperty("released_after_ms", std::to_string(ms(released_at - sent_at)));
    RecordProperty("octets_read", std::to_string(client.stream(large).data_bytes));
    client.close();
}

// A stream under way -- a request the server holds without answering -- when the server sends its error GOAWAY: the
// client then neither reads, nor writes, nor closes. The stream's context is cancelled when the session is released, at
// the GOAWAY: not linger() later, when the loop gives up on the client.
TEST_F(Http2ServerCloseAfterPeerTest, TheStreamsOfAConnectionAreCancelledWhenItsErrorGoawayIsSent) {
    Http2RawClient client;
    ASSERT_NO_FATAL_FAILURE(serving(client, port));
    ASSERT_NE(client.request("/hold"), 0u);
    ASSERT_TRUE(wait_until([&] { return probe.holding.load(); }, 10s)) << "the request never reached its handler";
    const std::int64_t sent_at = now_ns();
    ASSERT_NO_FATAL_FAILURE(connection_error(client));
    ASSERT_TRUE(wait_until([&] { return probe.cancelled_at.load() != 0; }, 6s)) << "the context of the stream under way was never cancelled";
    const std::int64_t cancelled_at = probe.cancelled_at.load();
    EXPECT_LT(cancelled_at - sent_at, (session_linger() / 2).count())
        << "the work of a connection the server had ended went on for " << ms(cancelled_at - sent_at) << " ms";
    RecordProperty("cancelled_after_ms", std::to_string(ms(cancelled_at - sent_at)));
    client.close();
    EXPECT_TRUE(loop_closes_nothing()) << "the server's loop still closes the socket of a client that closed";
}

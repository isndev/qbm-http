/**
 * @file qbm/http/tests/system/middleware/static-files-stream.cpp
 * @brief `StaticFilesMiddleware` streams a large body over a real HTTP/1.1 session (Huly QB-101).
 *
 * A real server runs on a worker thread (the shared @ref qb::http::test::ServerThread harness, on a port the system
 * assigns); the client is a RAW non-blocking socket on the test thread -- TCP, or TLS for the HTTPS case -- so every
 * assertion is on the bytes of the wire, and the client decides when it reads, which is what backpressure needs.
 * What the server decided (the status, whether the response streamed, the bytes it streamed, a cancellation) is
 * recorded by a request observer; the peak of the session's output, by the session's own `stream_pending()`, which
 * every write of a stream asks.
 *
 * One witness per decision of the change:
 *   - a body over `stream_threshold` streams under its Content-Length, every byte in order, and the connection serves
 *     the next request; a body at most the threshold is read whole, as before; a body an earlier middleware left is
 *     not streamed ahead of the file;
 *   - a client that does not read bounds the server's output under the session's high watermark and a piece, then
 *     gets every byte when it reads (the stalling clients negotiate a small receive window, and their file is larger
 *     than what any loopback socket buffers hold, so the stall is the producer's, whatever the host's TCP tuning);
 *   - Range, HEAD, If-None-Match, If-Modified-Since, If-Range and an unsatisfiable Range answer, head and body, exactly
 *     what the same server answers with streaming turned off (`stream_threshold` = SIZE_MAX);
 *   - `max_file_size` bounds a body read whole only: a streamed body over it is served, HEAD mirrors the GET, and a
 *     threshold above the cap still refuses what it would read whole;
 *   - a peer that leaves mid-body cancels the request; a file that shrinks under the read closes the connection short
 *     of its Content-Length; a session that drops what it is given (it is disconnecting) ends the request cancelled,
 *     not delivered, without the whole file read in one turn; an HTTP/1.0 request streams under its length;
 *     pipelined requests stay in order; a file being downloaded can be renamed away, replaced and its old name removed,
 *     on Windows too, the download reading the old bytes to its end;
 *   - PRE_RESPONSE_SEND hooks: one that drops the length streams chunked; one that leaves a head a stream cannot
 *     carry gets the body read whole, under the cap, and over it a 413 with the head of the historical one, a framing
 *     it added dropped; one that answers 304 leaves the file unread; one that ends the request gets no stream, and a
 *     503 that declares no body on a connection that serves on; compression leaves a streamed body alone and still
 *     compresses one read whole;
 *   - over TLS, the same stream, every byte.
 * HTTP/2 and HTTP/3 keep the buffered path: their cases are in the http2-client and http3-loopback suites.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * @ingroup Http
 */
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>
#include <qb/uuid.h>

#include "../../shared/loopback_server.h"

#include <qbm/http/http.h>
#include <qbm/http/middleware/compression.h>
#include <qbm/http/middleware/static_files.h>

#include <qb/io/tcp/socket.h>

#ifdef QB_HAS_SSL
#include <qb/io/tcp/ssl/socket.h>

#include "../../shared/tls_identity.h"
#endif

using namespace std::chrono_literals;
using qb::http::test::ServerThread;

namespace static_files_stream_test {

constexpr std::size_t kBig       = std::size_t{4} * 1024 * 1024;  ///< streamed under the suite's threshold
constexpr std::size_t kHuge      = std::size_t{16} * 1024 * 1024; ///< more than any loopback socket buffers hold
constexpr int         kClientRcv = 64 * 1024;                     ///< the receive buffer of a client that stalls
constexpr std::size_t kMid       = std::size_t{300} * 1024;       ///< over the threshold, under the suite's 1 MiB cap
constexpr std::size_t kSmall     = 100;                           ///< read whole
constexpr std::size_t kThreshold = std::size_t{64} * 1024;
constexpr std::size_t kCap       = std::size_t{1024} * 1024; ///< max_file_size where a case sets one below kBig
constexpr std::size_t kHighMark  = std::size_t{256} * 1024;  ///< the session high watermark of the backpressure cases
constexpr std::size_t kPiece     = qb::http::internal::static_file_stream_piece;

/// Bytes no two offsets of which are likely to agree, so a piece out of place or twice is seen.
std::string
pattern(std::size_t n, std::uint32_t seed) {
    std::string   s(n, '\0');
    std::uint32_t x = seed * 2654435761u + 1u;
    for (auto &c : s) {
        x = x * 1664525u + 1013904223u;
        c = static_cast<char>(x >> 24);
    }
    return s;
}

// ------------------------------------------------------------------------------------------------ what the server saw
struct Record {
    int         status    = 0;
    bool        streaming = false;
    bool        cancelled = false;
    std::size_t streamed  = 0; ///< ctx.streamed_bytes()
    std::size_t body      = 0; ///< the response body left in the context (a body read whole)
};
inline std::mutex                    g_mutex;
inline std::map<std::string, Record> g_records; ///< by the request's X-Probe header

inline std::optional<Record>
record_of(std::string const &probe) {
    std::lock_guard lock(g_mutex);
    const auto      it = g_records.find(probe);
    if (it == g_records.end())
        return std::nullopt;
    return it->second;
}

template <typename Session>
class Recorder final : public qb::http::IRequestObserver<Session> {
public:
    void
    on_response(qb::http::Context<Session> const &ctx, qb::http::RequestEnd const &) noexcept override {
        try {
            std::lock_guard lock(g_mutex);
            g_records[std::string(ctx.request().header("X-Probe"))] = Record{
                static_cast<int>(ctx.response().status().code()), ctx.is_streaming(), ctx.is_cancelled(), ctx.streamed_bytes(),
                ctx.response().body().size()
            };
        } catch (...) {
        }
    }
};

/// The peak of the session's output as its streams read it, and the high watermark the next session takes (0: the
/// session's default).
inline std::atomic<std::size_t> g_max_pending{0};
inline std::atomic<std::size_t> g_high_mark{0};

class FileServer;

class FileSession : public qb::http::use<FileSession>::session<FileServer> {
    using Base = qb::http::use<FileSession>::session<FileServer>;

public:
    explicit FileSession(FileServer &server_ref)
        : Base(server_ref) {
        if (const auto high = g_high_mark.load())
            this->stream_high_watermark(high);
    }

    /// The session's own answer, its peak recorded: a stream asks it before every write.
    [[nodiscard]] std::size_t
    stream_pending() noexcept {
        const auto  n    = Base::stream_pending();
        std::size_t seen = g_max_pending.load();
        while (n > seen && !g_max_pending.compare_exchange_weak(seen, n)) {
        }
        return n;
    }
};

class FileServer : public qb::http::use<FileServer>::server<FileSession> {};

using Router = qb::http::Router<FileSession>;

// The session of this suite streams: were it to fall back to buffering, the cases below would prove nothing.
static_assert(qb::http::streaming_session<FileSession>);

// ------------------------------------------------------------------------------------------------ the raw client
/// A raw non-blocking client (the same as the response-stream suite's): TCP, or TLS with the server's self-signed
/// certificate accepted. TLS reads answer 0 while OpenSSL waits for more bytes, and -1 once the connection is over.
template <typename Socket>
class BasicRawClient {
    Socket _sock;

    static constexpr bool tls = !std::is_same_v<Socket, qb::io::tcp::socket>;

public:
    std::string buffer;
    bool        eof = false;

    /// `receive_buffer` (TCP only): set before the connection, so the window is negotiated small and what the
    /// kernels hold for a client that does not read stays far under the files that stall it.
    bool
    connect(std::uint16_t port, int receive_buffer = 0) {
        if constexpr (tls)
            _sock.set_insecure(); // the server's certificate is self-signed
        else if (receive_buffer && (_sock.init(AF_INET) != 0 || _sock.set_optval(SOL_SOCKET, SO_RCVBUF, receive_buffer) != 0))
            return false;
        return _sock.connect_v4("127.0.0.1", port) == 0 && _sock.set_nonblocking(true) == 0;
    }

    bool
    send(std::string_view data, std::chrono::milliseconds budget = 2s) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (!data.empty()) {
            const int n = _sock.write(data.data(), data.size());
            if (n > 0) {
                data.remove_prefix(static_cast<std::size_t>(n));
                continue;
            }
            if (std::chrono::steady_clock::now() >= deadline)
                return false;
            std::this_thread::sleep_for(1ms);
        }
        return true;
    }

    /// Read what is there, once; true when something came. EOF is recorded.
    bool
    read_some() {
        char      tmp[64 * 1024];
        const int n = _sock.read(tmp, sizeof tmp);
        if (n > 0) {
            buffer.append(tmp, static_cast<std::size_t>(n));
            return true;
        }
        if constexpr (tls) {
            if (n < 0)
                eof = true;
        } else {
            if (n == 0 || !qb::io::socket::not_recv_error(qb::io::socket::get_last_errno()))
                eof = true; // an orderly close, or a reset: the connection is over either way
        }
        return false;
    }

    template <typename Pred>
    bool
    read_until(Pred &&pred, std::chrono::milliseconds budget = 20s) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (!pred()) {
            if (eof || std::chrono::steady_clock::now() >= deadline)
                return pred();
            if (!read_some())
                std::this_thread::sleep_for(1ms);
        }
        return true;
    }

    void
    close() {
        _sock.disconnect();
    }
};

using RawClient = BasicRawClient<qb::io::tcp::socket>;

/// One response parsed from the front of `wire`. `complete` once its whole body (by its Content-Length) is there.
struct Parsed {
    bool                               complete = false;
    int                                status   = 0;
    std::string                        head;
    std::map<std::string, std::string> fields; ///< lower-cased names; one value per name in this suite
    std::string                        body;
    std::size_t                        consumed = 0;

    [[nodiscard]] std::string
    field(std::string const &name) const {
        const auto it = fields.find(name);
        return it == fields.end() ? std::string{} : it->second;
    }
    [[nodiscard]] bool
    has(std::string const &name) const {
        return fields.count(name) != 0;
    }
};

Parsed
parse_response(std::string_view wire, bool head_request = false) {
    Parsed     p;
    const auto end_of_head = wire.find("\r\n\r\n");
    if (end_of_head == std::string_view::npos)
        return p;
    p.head   = std::string(wire.substr(0, end_of_head + 2));
    p.status = std::atoi(std::string(wire.substr(9, 3)).c_str());
    for (std::size_t line = p.head.find("\r\n") + 2; line < p.head.size();) {
        const auto end   = p.head.find("\r\n", line);
        const auto colon = p.head.find(':', line);
        if (colon != std::string::npos && colon < end) {
            std::string name = p.head.substr(line, colon - line);
            std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            auto value = p.head.substr(colon + 1, end - colon - 1);
            value.erase(0, value.find_first_not_of(' '));
            p.fields[name] = value;
        }
        line = end + 2;
    }
    const std::size_t pos = end_of_head + 4;
    if (head_request || p.status == 204 || p.status == 304) {
        p.complete = true;
        p.consumed = pos;
        return p;
    }
    if (p.has("content-length")) {
        const std::size_t length = std::stoul(p.field("content-length"));
        if (wire.size() < pos + length)
            return p;
        p.body     = std::string(wire.substr(pos, length));
        p.complete = true;
        p.consumed = pos + length;
    }
    return p;
}

std::string
request(std::string_view path, std::string_view probe, std::string_view extra = "", std::string_view method = "GET",
        std::string_view version = "HTTP/1.1") {
    return std::string(method) + " " + std::string(path) + " " + std::string(version) + "\r\nHost: 127.0.0.1\r\nX-Probe: " + std::string(probe)
           + "\r\n" + std::string(extra) + "\r\n";
}

template <typename Pred>
bool
wait_for(Pred &&pred, std::chrono::milliseconds budget = 10s) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        std::this_thread::sleep_for(1ms);
    }
    return true;
}

/// One exchange on a fresh connection: the response, parsed (and the raw client's EOF state).
struct Exchange {
    Parsed response;
    bool   eof = false;
};

template <typename Client = RawClient>
Exchange
exchange(std::uint16_t port, std::string const &wire, bool head_request = false) {
    Client c;
    if (!c.connect(port) || !c.send(wire))
        return {};
    c.read_until([&] { return parse_response(c.buffer, head_request).complete; });
    return {parse_response(c.buffer, head_request), c.eof};
}

// ------------------------------------------------------------------------------------------------ the fixture
class StaticFilesStreamTest : public ::testing::Test {
protected:
    std::filesystem::path root;
    std::string           big;
    std::string           mid;
    std::string           small;
    std::string           huge; ///< written by the cases that stall a client (write_huge())

    void
    write_file(std::string const &name, std::string const &content) {
        std::ofstream out(root / name, std::ios::binary | std::ios::trunc);
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        ASSERT_TRUE(static_cast<bool>(out)) << "cannot write " << (root / name);
    }

    void
    SetUp() override {
        {
            std::lock_guard lock(g_mutex);
            g_records.clear();
        }
        g_max_pending = 0;
        g_high_mark   = 0;
        root          = std::filesystem::temp_directory_path() / ("qbm-static-stream-" + uuids::to_string(qb::generate_random_uuid()));
        ASSERT_TRUE(std::filesystem::create_directories(root));
        big   = pattern(kBig, 1);
        mid   = pattern(kMid, 2);
        small = pattern(kSmall, 3);
        write_file("big.bin", big);
        write_file("mid.bin", mid);
        write_file("small.txt", small);
    }

    void
    TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    void
    write_huge() {
        huge = pattern(kHuge, 7);
        write_file("huge.bin", huge);
    }

    [[nodiscard]] qb::http::StaticFilesOptions
    options() const {
        return qb::http::StaticFilesOptions(root).with_path_prefix_to_strip("/static").with_stream_threshold(kThreshold);
    }

    /// A server with `opts`, the recorder first, `before` (middleware ahead of the static files) next.
    [[nodiscard]] static std::unique_ptr<ServerThread<FileServer>>
    serve(qb::http::StaticFilesOptions opts, std::function<void(Router &)> before = {}) {
        return std::make_unique<ServerThread<FileServer>>([opts = std::move(opts), before = std::move(before)](FileServer &s) {
            s.router().add_observer(std::make_shared<Recorder<FileSession>>());
            if (before)
                before(s.router());
            s.router().use(qb::http::static_files_middleware<FileSession>(opts));
            s.router().compile();
            if (s.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            s.start();
            return true;
        });
    }
};

/// A middleware ahead of the static files that adds a PRE_RESPONSE_SEND hook: what a hook may do to a head.
inline void
add_pre_send_hook(Router &router, std::function<void(qb::http::Context<FileSession> &)> hook) {
    router.use([hook = std::move(hook)](std::shared_ptr<qb::http::Context<FileSession>> ctx, std::function<void()> next) {
        ctx->add_lifecycle_hook([hook](qb::http::Context<FileSession> &c, qb::http::HookPoint point) {
            if (point == qb::http::HookPoint::PRE_RESPONSE_SEND)
                hook(c);
        });
        next();
    });
}

} // namespace static_files_stream_test

using namespace static_files_stream_test;

TEST_F(StaticFilesStreamTest, ABodyOverTheThresholdStreamsEveryByteUnderItsLengthAndKeepsTheConnection) {
    auto server = serve(options());
    ASSERT_TRUE(server->ready());
    RawClient c;
    ASSERT_TRUE(c.connect(server->port()));
    ASSERT_TRUE(c.send(request("/static/big.bin", "big")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer.substr(0, 512);
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.field("content-length"), std::to_string(kBig)) << r.head;
    EXPECT_FALSE(r.has("transfer-encoding")) << "identity framing under the declared length: " << r.head;
    EXPECT_EQ(r.field("content-type"), "application/octet-stream");
    EXPECT_TRUE(r.body == big) << "the streamed bytes differ from the file's";
    ASSERT_TRUE(wait_for([] { return record_of("big").has_value(); }));
    const auto seen = *record_of("big");
    EXPECT_TRUE(seen.streaming) << "a body over the threshold must stream on HTTP/1.1";
    EXPECT_EQ(seen.streamed, kBig);
    EXPECT_EQ(seen.body, 0u) << "a streamed body is never gathered in the response";

    // The same connection serves the next request; a body at most the threshold is read whole, as before.
    c.buffer.erase(0, r.consumed);
    ASSERT_TRUE(c.send(request("/static/small.txt", "small")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    const auto s = parse_response(c.buffer);
    EXPECT_EQ(s.status, 200);
    EXPECT_EQ(s.body, small);
    ASSERT_TRUE(wait_for([] { return record_of("small").has_value(); }));
    EXPECT_FALSE(record_of("small")->streaming) << "a body at most the threshold is read whole";
    EXPECT_EQ(record_of("small")->body, kSmall);
}

TEST_F(StaticFilesStreamTest, ABodyOfExactlyTheThresholdIsReadWholeAndOneByteMoreStreams) {
    write_file("at.bin", pattern(kThreshold, 4));
    write_file("over.bin", pattern(kThreshold + 1, 5));
    auto server = serve(options());
    ASSERT_TRUE(server->ready());
    const auto at   = exchange(server->port(), request("/static/at.bin", "at"));
    const auto over = exchange(server->port(), request("/static/over.bin", "over"));
    EXPECT_EQ(at.response.body, pattern(kThreshold, 4));
    EXPECT_EQ(over.response.body, pattern(kThreshold + 1, 5));
    ASSERT_TRUE(wait_for([] { return record_of("at") && record_of("over"); }));
    EXPECT_FALSE(record_of("at")->streaming) << "the threshold is the largest body read whole";
    EXPECT_TRUE(record_of("over")->streaming);
}

TEST_F(StaticFilesStreamTest, AClientThatDoesNotReadBoundsTheServersOutputThenGetsEveryByte) {
    g_high_mark = kHighMark;
    write_huge();
    auto server = serve(options());
    ASSERT_TRUE(server->ready());
    RawClient c;
    ASSERT_TRUE(c.connect(server->port(), kClientRcv));
    ASSERT_TRUE(c.send(request("/static/huge.bin", "stall")));
    // Nothing is read. The first turn fills the session's output to the mark; what the kernels take of it is far
    // under the file, so the producer then waits on a drain that does not come. A producer that ignored the mark
    // would have the whole file in the output.
    ASSERT_TRUE(wait_for([] { return g_max_pending.load() >= kHighMark; })) << "the output never reached the mark: " << g_max_pending.load();
    std::this_thread::sleep_for(200ms);
    EXPECT_FALSE(record_of("stall").has_value()) << "the response cannot be over while the client reads nothing";
    EXPECT_LT(g_max_pending.load(), kHighMark + kPiece) << "the output passed the high watermark and a piece";

    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; }, 60s)) << "eof=" << c.eof;
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.status, 200);
    EXPECT_TRUE(r.body == huge) << "the bytes after the drains differ from the file's";
    EXPECT_LT(g_max_pending.load(), kHighMark + kPiece);
    ASSERT_TRUE(wait_for([] { return record_of("stall").has_value(); }));
    EXPECT_TRUE(record_of("stall")->streaming);
    EXPECT_EQ(record_of("stall")->streamed, kHuge);
}

TEST_F(StaticFilesStreamTest, ARangeOverTheThresholdStreamsThePartAskedAndASmallOneIsReadWhole) {
    auto server = serve(options());
    ASSERT_TRUE(server->ready());
    const auto wide = exchange(server->port(), request("/static/big.bin", "wide", "Range: bytes=100000-2999999\r\n"));
    EXPECT_EQ(wide.response.status, 206);
    EXPECT_EQ(wide.response.field("content-range"), "bytes 100000-2999999/" + std::to_string(kBig));
    EXPECT_EQ(wide.response.field("content-length"), "2900000");
    EXPECT_TRUE(wide.response.body == big.substr(100000, 2900000)) << "the streamed range differs from the file's";

    const auto suffix = exchange(server->port(), request("/static/big.bin", "suffix", "Range: bytes=-2000000\r\n"));
    EXPECT_EQ(suffix.response.status, 206);
    EXPECT_EQ(suffix.response.field("content-range"),
              "bytes " + std::to_string(kBig - 2000000) + "-" + std::to_string(kBig - 1) + "/" + std::to_string(kBig));
    EXPECT_TRUE(suffix.response.body == big.substr(kBig - 2000000));

    const auto narrow = exchange(server->port(), request("/static/big.bin", "narrow", "Range: bytes=7-106\r\n"));
    EXPECT_EQ(narrow.response.status, 206);
    EXPECT_EQ(narrow.response.body, big.substr(7, 100));

    ASSERT_TRUE(wait_for([] { return record_of("wide") && record_of("suffix") && record_of("narrow"); }));
    EXPECT_TRUE(record_of("wide")->streaming);
    EXPECT_EQ(record_of("wide")->streamed, 2900000u);
    EXPECT_TRUE(record_of("suffix")->streaming);
    EXPECT_FALSE(record_of("narrow")->streaming) << "the threshold is read against the body sent, not the file";
}

// The decisive check that nothing but the delivery changed: every conditional and partial form, head and body,
// against the same server with streaming turned off.
TEST_F(StaticFilesStreamTest, AStreamingServerAnswersEveryFormWithTheHeadAndBodyOfABufferedOne) {
    auto streaming = serve(options());
    auto buffered  = serve(options().with_stream_threshold(std::numeric_limits<std::size_t>::max()));
    ASSERT_TRUE(streaming->ready());
    ASSERT_TRUE(buffered->ready());

    const auto probe = exchange(buffered->port(), request("/static/big.bin", "etag"));
    const auto etag  = probe.response.field("etag");
    const auto date  = probe.response.field("last-modified");
    ASSERT_FALSE(etag.empty());
    ASSERT_FALSE(date.empty());
    const std::string strong = "\"" + etag.substr(etag.find('"') + 1); // the weak tag as a strong one: If-Range ignores Range

    struct Form {
        const char *name;
        std::string extra;
        const char *method;
        int         status;
    };
    const std::vector<Form> forms = {
        {"full", "", "GET", 200},
        {"head", "", "HEAD", 200},
        {"range", "Range: bytes=4096-3999999\r\n", "GET", 206},
        {"suffix", "Range: bytes=-1500000\r\n", "GET", 206},
        {"open-range", "Range: bytes=2000000-\r\n", "GET", 206},
        {"if-none-match", "If-None-Match: " + etag + "\r\n", "GET", 304},
        {"if-none-match-miss", "If-None-Match: \"other\"\r\n", "GET", 200},
        {"if-modified-since", "If-Modified-Since: " + date + "\r\n", "GET", 304},
        {"if-range-weak", "Range: bytes=0-1999999\r\nIf-Range: " + etag + "\r\n", "GET", 200},
        {"if-range-strong-miss", "Range: bytes=0-1999999\r\nIf-Range: " + strong + "\r\n", "GET", 200},
        {"unsatisfiable", "Range: bytes=9999999-\r\n", "GET", 416},
        {"multi-range", "Range: bytes=0-10,20-30\r\n", "GET", 416},
    };
    for (auto const &form : forms) {
        SCOPED_TRACE(form.name);
        const bool head = std::string_view(form.method) == "HEAD";
        const auto s    = exchange(streaming->port(), request("/static/big.bin", std::string("s-") + form.name, form.extra, form.method), head);
        const auto b    = exchange(buffered->port(), request("/static/big.bin", std::string("b-") + form.name, form.extra, form.method), head);
        ASSERT_TRUE(s.response.complete) << s.response.head;
        ASSERT_TRUE(b.response.complete) << b.response.head;
        EXPECT_EQ(s.response.status, form.status);
        EXPECT_EQ(s.response.status, b.response.status);
        auto sf = s.response.fields;
        auto bf = b.response.fields;
        sf.erase("date");
        bf.erase("date");
        EXPECT_EQ(sf, bf) << "streamed head:\n" << s.response.head << "buffered head:\n" << b.response.head;
        EXPECT_TRUE(s.response.body == b.response.body) << "bodies differ: " << s.response.body.size() << " vs " << b.response.body.size();
    }
    ASSERT_TRUE(wait_for([] { return record_of("s-full") && record_of("s-range") && record_of("s-head"); }));
    EXPECT_TRUE(record_of("s-full")->streaming) << "the differential must compare a streamed response to a buffered one";
    EXPECT_TRUE(record_of("s-range")->streaming);
    EXPECT_FALSE(record_of("s-head")->streaming) << "HEAD is answered whole at its head";
    EXPECT_FALSE(record_of("b-full")->streaming);
}

TEST_F(StaticFilesStreamTest, MaxFileSizeBoundsOnlyABodyReadWhole) {
    // Streams: the cap does not apply -- to the GET, to a range over it, nor to the HEAD that mirrors the GET.
    auto streaming = serve(options().with_max_file_size(kCap));
    // Reads whole: the cap applies, as it always did -- to the file, even for a range under it.
    auto buffered = serve(options().with_max_file_size(kCap).with_stream_threshold(std::numeric_limits<std::size_t>::max()));
    // A threshold above the cap: what it reads whole is still refused over the cap.
    auto high = serve(options().with_max_file_size(kCap).with_stream_threshold(2 * kCap));
    ASSERT_TRUE(streaming->ready());
    ASSERT_TRUE(buffered->ready());
    ASSERT_TRUE(high->ready());

    const auto get = exchange(streaming->port(), request("/static/big.bin", "get"));
    EXPECT_EQ(get.response.status, 200);
    EXPECT_TRUE(get.response.body == big);
    const auto head = exchange(streaming->port(), request("/static/big.bin", "head", "", "HEAD"), true);
    EXPECT_EQ(head.response.status, 200) << head.response.head;
    EXPECT_EQ(head.response.field("content-length"), std::to_string(kBig));
    const auto range = exchange(streaming->port(), request("/static/big.bin", "range", "Range: bytes=0-1499999\r\n"));
    EXPECT_EQ(range.response.status, 206);
    EXPECT_TRUE(range.response.body == big.substr(0, 1500000));
    const auto small_range = exchange(streaming->port(), request("/static/big.bin", "small-range", "Range: bytes=10-19\r\n"));
    EXPECT_EQ(small_range.response.status, 206) << "a small range of a file over the cap: the file streams, the range is read whole";
    EXPECT_EQ(small_range.response.body, big.substr(10, 10));

    EXPECT_EQ(exchange(buffered->port(), request("/static/big.bin", "b-get")).response.status, 413);
    EXPECT_EQ(exchange(buffered->port(), request("/static/big.bin", "b-head", "", "HEAD"), true).response.status, 413);
    EXPECT_EQ(exchange(buffered->port(), request("/static/big.bin", "b-small-range", "Range: bytes=10-19\r\n")).response.status, 413)
        << "unchanged: a file over the cap is refused before its range is read";

    const auto over = exchange(high->port(), request("/static/big.bin", "h-range", "Range: bytes=0-1499999\r\n"));
    EXPECT_EQ(over.response.status, 413) << "1.5 MB is at most the 2 MiB threshold: read whole, so over the 1 MiB cap";
    const auto streams = exchange(high->port(), request("/static/big.bin", "h-get"));
    EXPECT_EQ(streams.response.status, 200) << "4 MiB is over the threshold: it streams";
    EXPECT_TRUE(streams.response.body == big);
}

TEST_F(StaticFilesStreamTest, APeerThatLeavesMidBodyCancelsTheRequestAndTheServerServesOn) {
    g_high_mark = kHighMark;
    write_huge();
    auto server = serve(options());
    ASSERT_TRUE(server->ready());
    {
        RawClient c;
        ASSERT_TRUE(c.connect(server->port(), kClientRcv));
        ASSERT_TRUE(c.send(request("/static/huge.bin", "gone")));
        ASSERT_TRUE(c.read_until([&] { return c.buffer.size() > 4096; }));
        ASSERT_TRUE(wait_for([] { return g_max_pending.load() >= kHighMark; })) << "the output never reached the mark";
        c.close(); // the kernels hold far less than the file: the stream is mid-body
    }
    ASSERT_TRUE(wait_for([] { return record_of("gone").has_value(); })) << "the request never ended after its peer left";
    const auto gone = *record_of("gone");
    EXPECT_TRUE(gone.streaming);
    EXPECT_TRUE(gone.cancelled);
    EXPECT_LT(gone.streamed, kHuge);
    const auto next = exchange(server->port(), request("/static/mid.bin", "next"));
    EXPECT_EQ(next.response.status, 200);
    EXPECT_TRUE(next.response.body == mid);
}

TEST_F(StaticFilesStreamTest, AFileThatShrinksUnderTheReadClosesTheConnectionShortOfItsLength) {
    // A file cut to its half under the read: the kernels and the session's output hold far less than that (a few MiB
    // at most, with the client's small window) when the producer stalls, so the cut lands ahead of the producer.
    g_high_mark          = kHighMark;
    const auto shrinking = pattern(kHuge, 6);
    write_file("shrink.bin", shrinking);
    auto server = serve(options());
    ASSERT_TRUE(server->ready());
    RawClient c;
    ASSERT_TRUE(c.connect(server->port(), kClientRcv));
    ASSERT_TRUE(c.send(request("/static/shrink.bin", "shrink")));
    ASSERT_TRUE(c.read_until([&] { return c.buffer.find("\r\n\r\n") != std::string::npos; }));
    ASSERT_TRUE(wait_for([] { return g_max_pending.load() >= kHighMark; })) << "the output never reached the mark";
    std::filesystem::resize_file(root / "shrink.bin", kHuge / 2);
    c.read_until([] { return false; }); // to the end of the connection
    EXPECT_TRUE(c.eof) << "the server must close a message it can no longer complete";
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.field("content-length"), std::to_string(kHuge));
    EXPECT_FALSE(r.complete) << "the client must see fewer bytes than declared";
    const auto received = c.buffer.size() - (c.buffer.find("\r\n\r\n") + 4);
    EXPECT_LE(received, kHuge / 2);
    EXPECT_TRUE(c.buffer.compare(c.buffer.find("\r\n\r\n") + 4, received, shrinking, 0, received) == 0) << "what left is the file's prefix";
    ASSERT_TRUE(wait_for([] { return record_of("shrink").has_value(); }));
    EXPECT_TRUE(record_of("shrink")->cancelled) << "an aborted stream cancels its request";
}

// An operator replaces a file a slow client is downloading: the new one is written beside it, the served one renamed
// away, the new one renamed in, the old name removed. Every step succeeds while the download reads; the download ends
// with the old bytes, and the next request gets the new file. On Windows the read used to hold the file without
// delete-sharing until its last byte -- every rename and the removal refused for as long as the client took (Huly
// QB-101); the file is opened through qb-io's descriptor now, which shares delete (Huly QB-320).
TEST_F(StaticFilesStreamTest, AFileBeingDownloadedCanBeRenamedAwayReplacedAndRemoved) {
    g_high_mark = kHighMark;
    write_huge();
    const auto fresh = pattern(kBig, 8);
    write_file("huge.new", fresh);
    auto server = serve(options());
    ASSERT_TRUE(server->ready());
    RawClient c;
    ASSERT_TRUE(c.connect(server->port(), kClientRcv));
    ASSERT_TRUE(c.send(request("/static/huge.bin", "replaced")));
    ASSERT_TRUE(c.read_until([&] { return c.buffer.find("\r\n\r\n") != std::string::npos; }));
    // The client reads nothing more: the producer is parked mid-file, the file open.
    ASSERT_TRUE(wait_for([] { return g_max_pending.load() >= kHighMark; })) << "the output never reached the mark";
    ASSERT_FALSE(record_of("replaced").has_value()) << "the download must still be in flight";

    std::error_code away, in, removed;
    std::filesystem::rename(root / "huge.bin", root / "huge.old", away);
    EXPECT_FALSE(away) << "renaming a file being downloaded away: " << away.message();
    std::filesystem::rename(root / "huge.new", root / "huge.bin", in);
    EXPECT_FALSE(in) << "putting the new file in its place: " << in.message();
    std::filesystem::remove(root / "huge.old", removed);
    EXPECT_FALSE(removed) << "removing the old name while the download reads it: " << removed.message();

    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; }, 60s)) << "eof=" << c.eof;
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.field("content-length"), std::to_string(kHuge));
    EXPECT_TRUE(r.body == huge) << "the download in flight must read the file it began with to its end";
    ASSERT_TRUE(wait_for([] { return record_of("replaced").has_value(); }));
    EXPECT_FALSE(record_of("replaced")->cancelled);
    EXPECT_EQ(record_of("replaced")->streamed, kHuge);

    const auto next = exchange(server->port(), request("/static/huge.bin", "replacement"));
    EXPECT_EQ(next.response.status, 200);
    EXPECT_EQ(next.response.field("content-length"), std::to_string(kBig));
    EXPECT_TRUE(next.response.body == fresh) << "the next request must get the file now at that name";
    std::error_code ec;
    EXPECT_FALSE(std::filesystem::exists(root / "huge.old", ec)) << "the old name outlived the download";
}

TEST_F(StaticFilesStreamTest, AnHttp10RequestStreamsUnderItsLengthThenTheConnectionCloses) {
    auto server = serve(options());
    ASSERT_TRUE(server->ready());
    RawClient c;
    ASSERT_TRUE(c.connect(server->port()));
    ASSERT_TRUE(c.send(request("/static/big.bin", "http10", "", "GET", "HTTP/1.0")));
    c.read_until([] { return false; });
    EXPECT_TRUE(c.eof);
    const auto r = parse_response(c.buffer);
    ASSERT_TRUE(r.complete) << r.head;
    EXPECT_EQ(r.field("content-length"), std::to_string(kBig));
    EXPECT_TRUE(r.body == big);
    EXPECT_EQ(r.consumed, c.buffer.size()) << "nothing follows the declared length";
    ASSERT_TRUE(wait_for([] { return record_of("http10").has_value(); }));
    EXPECT_TRUE(record_of("http10")->streaming) << "a declared length streams to HTTP/1.0 too";
}

TEST_F(StaticFilesStreamTest, PipelinedRequestsAreAnsweredInOrderAfterAStreamedOne) {
    auto server = serve(options());
    ASSERT_TRUE(server->ready());
    RawClient c;
    ASSERT_TRUE(c.connect(server->port()));
    ASSERT_TRUE(c.send(request("/static/big.bin", "p1") + request("/static/small.txt", "p2") + request("/static/mid.bin", "p3")));
    std::vector<Parsed> responses;
    ASSERT_TRUE(c.read_until([&] {
        while (true) {
            auto p = parse_response(c.buffer);
            if (!p.complete)
                return responses.size() == 3;
            c.buffer.erase(0, p.consumed);
            responses.push_back(std::move(p));
        }
    }));
    ASSERT_EQ(responses.size(), 3u);
    EXPECT_TRUE(responses[0].body == big);
    EXPECT_EQ(responses[1].body, small);
    EXPECT_TRUE(responses[2].body == mid);
}

TEST_F(StaticFilesStreamTest, AHookThatLeavesAnUnstreamableHeadGetsTheBodyReadWholeUnderTheCap) {
    // The hook drops the declared length; an HTTP/1.0 request reads no chunked body: the stream is buffered.
    auto server = serve(options().with_max_file_size(kCap), [](Router &router) {
        add_pre_send_hook(router, [](qb::http::Context<FileSession> &c) { c.response().remove_header("Content-Length"); });
    });
    ASSERT_TRUE(server->ready());
    const auto within = exchange(server->port(), request("/static/mid.bin", "within", "", "GET", "HTTP/1.0"));
    EXPECT_EQ(within.response.status, 200) << within.response.head;
    EXPECT_EQ(within.response.field("content-length"), std::to_string(kMid)) << "the serializer declares the body read whole";
    EXPECT_TRUE(within.response.body == mid);
    const auto over = exchange(server->port(), request("/static/big.bin", "over", "", "GET", "HTTP/1.0"));
    EXPECT_EQ(over.response.status, 413) << over.response.head;
    EXPECT_EQ(over.response.body, "File exceeds configured max_file_size");
    EXPECT_FALSE(over.response.has("content-range"));
    // The head of the 413 a server that reads every body whole gives the same request: no caching policy, no range.
    auto buffered = serve(options().with_max_file_size(kCap).with_stream_threshold(std::numeric_limits<std::size_t>::max()));
    ASSERT_TRUE(buffered->ready());
    const auto reference = exchange(buffered->port(), request("/static/big.bin", "reference", "", "GET", "HTTP/1.0"));
    ASSERT_EQ(reference.response.status, 413);
    auto ours   = over.response.fields;
    auto theirs = reference.response.fields;
    ours.erase("date");
    theirs.erase("date");
    EXPECT_EQ(ours, theirs) << "fallback 413:\n" << over.response.head << "historical 413:\n" << reference.response.head;
    const auto range = exchange(server->port(), request("/static/big.bin", "over-range", "Range: bytes=0-1999999\r\n", "GET", "HTTP/1.0"));
    EXPECT_EQ(range.response.status, 413) << range.response.head;
    EXPECT_FALSE(range.response.has("content-range")) << "the range no longer describes the body";
    ASSERT_TRUE(wait_for([] { return record_of("within") && record_of("over") && record_of("over-range"); }));
    EXPECT_FALSE(record_of("within")->streaming);
    EXPECT_EQ(record_of("within")->body, kMid);
    EXPECT_FALSE(record_of("over")->streaming);
}

// The same through complete(CANCELLED), which finalises without cancel(): the answer is the same 503, and a range's
// Content-Range goes with the length.
TEST_F(StaticFilesStreamTest, AHookThatCompletesTheRequestCancelledGetsTheSame503) {
    auto server = serve(options(), [](Router &router) {
        add_pre_send_hook(router, [](qb::http::Context<FileSession> &c) {
            if (c.request().uri().path() == "/static/big.bin")
                c.complete(qb::http::AsyncTaskResult::CANCELLED);
        });
    });
    ASSERT_TRUE(server->ready());
    RawClient c;
    ASSERT_TRUE(c.connect(server->port()));
    ASSERT_TRUE(c.send(request("/static/big.bin", "completed-cancelled", "Range: bytes=0-2999999\r\n")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer.substr(0, 512);
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.status, 503) << r.head;
    EXPECT_EQ(r.field("content-length"), "0") << r.head;
    EXPECT_FALSE(r.has("content-range")) << r.head;
    EXPECT_FALSE(r.has("cache-control")) << r.head;
    ASSERT_TRUE(wait_for([] { return record_of("completed-cancelled").has_value(); }));
    EXPECT_TRUE(record_of("completed-cancelled")->cancelled);
    c.buffer.erase(0, r.consumed);
    ASSERT_TRUE(c.send(request("/static/small.txt", "after-completed-cancelled")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << "the connection must serve on";
    EXPECT_EQ(parse_response(c.buffer).body, small);
}

// A middleware that answers the cancelled request itself, after next(): its answer is the one sent. The cancellation's
// 503 lands when the request is cancelled, inside the static files, before the middleware's deferral scope lets the
// request finalise -- not after what the middleware wrote.
TEST_F(StaticFilesStreamTest, AMiddlewareAnswersARequestAHookCancelledAfterNext) {
    auto server = serve(options(), [](Router &router) {
        router.use([](std::shared_ptr<qb::http::Context<FileSession>> ctx, std::function<void()> next) {
            ctx->add_lifecycle_hook([](qb::http::Context<FileSession> &c, qb::http::HookPoint point) {
                if (point == qb::http::HookPoint::PRE_RESPONSE_SEND && c.request().uri().path() == "/static/big.bin")
                    c.cancel("maintenance");
            });
            next(); // the static files run here, synchronously
            if (ctx->is_cancelled()) {
                ctx->response().body() = "Down for maintenance";
                ctx->response().set_header("Retry-After", "60");
                ctx->response().set_header("Cache-Control", "no-store");
                ctx->complete(qb::http::AsyncTaskResult::CANCELLED); // a second cancellation leaves the answer alone
            }
        });
    });
    ASSERT_TRUE(server->ready());
    RawClient c;
    ASSERT_TRUE(c.connect(server->port()));
    ASSERT_TRUE(c.send(request("/static/big.bin", "maintenance")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer.substr(0, 512);
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.status, 503) << r.head;
    EXPECT_EQ(r.body, "Down for maintenance") << r.head;
    EXPECT_EQ(r.field("retry-after"), "60");
    EXPECT_EQ(r.field("cache-control"), "no-store");
    c.buffer.erase(0, r.consumed);
    ASSERT_TRUE(c.send(request("/static/small.txt", "after-maintenance")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << "the connection must serve on";
    EXPECT_EQ(parse_response(c.buffer).body, small);
}

// A hook's bodiless status: the file is not read, and its length leaves with it -- a 204 cannot carry one, and a
// cancellation after the answer was decided must not answer 503 under the file's length.
TEST_F(StaticFilesStreamTest, AHookThatAnswersWithoutABodyGetsAHeadWithoutTheFilesLength) {
    auto server = serve(options(), [](Router &router) {
        router.use([](std::shared_ptr<qb::http::Context<FileSession>> ctx, std::function<void()> next) {
            const auto path = std::string(ctx->request().uri().path());
            ctx->add_lifecycle_hook([path](qb::http::Context<FileSession> &c, qb::http::HookPoint point) {
                if (point != qb::http::HookPoint::PRE_RESPONSE_SEND)
                    return;
                if (path == "/static/big.bin")
                    c.response().status() = qb::http::status::NO_CONTENT;
                else if (path == "/static/mid.bin")
                    c.response().status() = qb::http::status::NOT_MODIFIED;
            });
            next();
            if (path == "/static/mid.bin")
                ctx->cancel("cancelled after its answer was decided");
        });
    });
    ASSERT_TRUE(server->ready());
    RawClient c;
    ASSERT_TRUE(c.connect(server->port()));
    ASSERT_TRUE(c.send(request("/static/big.bin", "no-content")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer.substr(0, 512);
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.status, 204) << r.head;
    EXPECT_FALSE(r.has("content-length")) << "a 204 carries no length: " << r.head;
    EXPECT_FALSE(r.has("content-type")) << r.head;
    c.buffer.erase(0, r.consumed);
    ASSERT_TRUE(c.send(request("/static/mid.bin", "decided-then-cancelled")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer.substr(0, 512);
    const auto d = parse_response(c.buffer);
    EXPECT_EQ(d.status, 503) << d.head;
    EXPECT_EQ(d.field("content-length"), "0") << "a 503 under the file's length leaves the client waiting: " << d.head;
    c.buffer.erase(0, d.consumed);
    ASSERT_TRUE(c.send(request("/static/small.txt", "after-bodiless")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << "the connection must serve on";
    EXPECT_EQ(parse_response(c.buffer).body, small);
}

// An earlier middleware that completes the request and still calls next() (a contract it breaks): begin_stream()
// refuses a context whose completion is pending, and the file is read whole, as before streaming -- not a 200 that
// declares the file's length and carries nothing.
TEST_F(StaticFilesStreamTest, ARefusedStreamFallsBackToAWholeRead) {
    auto server = serve(options(), [](Router &router) {
        router.use([](std::shared_ptr<qb::http::Context<FileSession>> ctx, std::function<void()> next) {
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE); // held back by this middleware's own deferral scope
            next();
        });
    });
    ASSERT_TRUE(server->ready());
    const auto r = exchange(server->port(), request("/static/big.bin", "refused"));
    ASSERT_TRUE(r.response.complete) << r.response.head;
    EXPECT_EQ(r.response.status, 200);
    EXPECT_TRUE(r.response.body == big) << "the file read whole differs from the file's";
    ASSERT_TRUE(wait_for([] { return record_of("refused").has_value(); }));
    EXPECT_FALSE(record_of("refused")->streaming);
}

TEST_F(StaticFilesStreamTest, AHookThatAddsASecondFramingGetsTheHistorical413OverTheCap) {
    // A Content-Length and a Transfer-Encoding: the stream cannot carry both and is buffered; the body is over the cap,
    // so the answer is the 413 of a server that reads every body whole -- the framing the hook added dropped with ours.
    auto server   = serve(options().with_max_file_size(kCap), [](Router &router) {
        add_pre_send_hook(router, [](qb::http::Context<FileSession> &c) {
            if (c.response().status() == qb::http::status::OK)
                c.response().set_header("Transfer-Encoding", "chunked");
        });
    });
    auto buffered = serve(options().with_max_file_size(kCap).with_stream_threshold(std::numeric_limits<std::size_t>::max()));
    ASSERT_TRUE(server->ready());
    ASSERT_TRUE(buffered->ready());
    const auto over = exchange(server->port(), request("/static/big.bin", "framing"));
    ASSERT_TRUE(over.response.complete) << over.response.head;
    EXPECT_EQ(over.response.status, 413);
    EXPECT_EQ(over.response.body, "File exceeds configured max_file_size");
    const auto reference = exchange(buffered->port(), request("/static/big.bin", "framing-reference"));
    ASSERT_EQ(reference.response.status, 413);
    auto ours   = over.response.fields;
    auto theirs = reference.response.fields;
    ours.erase("date");
    theirs.erase("date");
    EXPECT_EQ(ours, theirs) << "fallback 413:\n" << over.response.head << "historical 413:\n" << reference.response.head;
}

TEST_F(StaticFilesStreamTest, AHookThatAnswers304LeavesTheFileUnread) {
    auto server = serve(options(), [](Router &router) {
        add_pre_send_hook(router, [](qb::http::Context<FileSession> &c) {
            if (c.request().uri().path() == "/static/big.bin")
                c.response().status() = qb::http::status::NOT_MODIFIED;
        });
    });
    ASSERT_TRUE(server->ready());
    RawClient c;
    ASSERT_TRUE(c.connect(server->port()));
    ASSERT_TRUE(c.send(request("/static/big.bin", "304")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; }));
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.status, 304);
    c.buffer.erase(0, r.consumed);
    ASSERT_TRUE(c.send(request("/static/small.txt", "after")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << "no body byte may follow a 304: " << c.buffer.size();
    EXPECT_EQ(parse_response(c.buffer).body, small);
    ASSERT_TRUE(wait_for([] { return record_of("304").has_value(); }));
    EXPECT_FALSE(record_of("304")->streaming);
    EXPECT_EQ(record_of("304")->body, 0u) << "the file was read for a response that carries no body";
}

TEST_F(StaticFilesStreamTest, ABodyAnEarlierMiddlewareLeftIsNotStreamedAheadOfTheFile) {
    auto server = serve(options(), [](Router &router) {
        router.use([](std::shared_ptr<qb::http::Context<FileSession>> ctx, std::function<void()> next) {
            ctx->response().body() = "left-by-an-earlier-middleware";
            next();
        });
    });
    ASSERT_TRUE(server->ready());
    const auto streamed = exchange(server->port(), request("/static/big.bin", "left-big"));
    ASSERT_TRUE(streamed.response.complete) << streamed.response.head;
    EXPECT_EQ(streamed.response.field("content-length"), std::to_string(kBig));
    EXPECT_TRUE(streamed.response.body == big) << "the file is the body, as when it is read whole";
    const auto whole = exchange(server->port(), request("/static/small.txt", "left-small"));
    EXPECT_EQ(whole.response.body, small);
    ASSERT_TRUE(wait_for([] { return record_of("left-big").has_value(); }));
    EXPECT_TRUE(record_of("left-big")->streaming);
    EXPECT_FALSE(record_of("left-big")->cancelled);
}

TEST_F(StaticFilesStreamTest, AHookThatDropsTheLengthStreamsChunked) {
    // A high mark under two full pieces: a piece is half the mark, so a chunk and its framing fit a drained output.
    constexpr std::size_t kSmallMark = std::size_t{64} * 1024;
    g_high_mark                      = kSmallMark;
    auto server                      = serve(options(), [](Router &router) {
        add_pre_send_hook(router, [](qb::http::Context<FileSession> &c) { c.response().remove_header("Content-Length"); });
    });
    ASSERT_TRUE(server->ready());
    RawClient c;
    ASSERT_TRUE(c.connect(server->port()));
    ASSERT_TRUE(c.send(request("/static/big.bin", "chunked")));
    // A chunked body: the last-chunk ends it.
    ASSERT_TRUE(c.read_until([&] { return c.buffer.size() >= 5 && c.buffer.compare(c.buffer.size() - 5, 5, "0\r\n\r\n") == 0; }))
        << c.buffer.substr(0, 256);
    const auto head_end = c.buffer.find("\r\n\r\n");
    ASSERT_NE(head_end, std::string::npos);
    const auto head = parse_response(std::string_view(c.buffer).substr(0, head_end + 4), true);
    EXPECT_EQ(head.field("transfer-encoding"), "chunked") << head.head;
    EXPECT_FALSE(head.has("content-length"));
    std::string body;
    std::size_t chunks = 0;
    for (std::size_t pos = head_end + 4;;) {
        const auto line_end = c.buffer.find("\r\n", pos);
        ASSERT_NE(line_end, std::string::npos);
        const std::size_t size = std::stoul(c.buffer.substr(pos, line_end - pos), nullptr, 16);
        if (size == 0)
            break;
        EXPECT_LE(size, kSmallMark / 2) << "a piece is at most half the high mark";
        body.append(c.buffer, line_end + 2, size);
        ++chunks;
        pos = line_end + 2 + size + 2;
    }
    EXPECT_TRUE(body == big) << "the chunked bytes differ from the file's";
    EXPECT_GE(chunks, kBig / (kSmallMark / 2));
    ASSERT_TRUE(wait_for([] { return record_of("chunked").has_value(); }));
    EXPECT_TRUE(record_of("chunked")->streaming);
    EXPECT_EQ(record_of("chunked")->streamed, kBig);
}

// A session that is disconnecting takes what it is given without queuing it until its io is disposed: the stream's
// writes are "taken" and its output never fills. A producer that only waited for the mark would read the whole file in
// that turn and end the stream as if delivered; one turn writes at most a fill and a piece, then gives the turn back.
TEST_F(StaticFilesStreamTest, ASessionThatDropsWhatItIsGivenEndsTheStreamCancelledNotDelivered) {
    write_huge();
    auto server = serve(options(), [](Router &router) {
        add_pre_send_hook(router, [](qb::http::Context<FileSession> &c) {
            auto session = c.session();
            if (session && c.request().uri().path() == "/static/huge.bin")
                session->disconnect(); // the head that follows is dropped, and every piece after it
        });
    });
    ASSERT_TRUE(server->ready());
    RawClient c;
    ASSERT_TRUE(c.connect(server->port()));
    ASSERT_TRUE(c.send(request("/static/huge.bin", "dropped")));
    ASSERT_TRUE(wait_for([] { return record_of("dropped").has_value(); })) << "the request never ended";
    const auto dropped = *record_of("dropped");
    EXPECT_TRUE(dropped.streaming);
    EXPECT_TRUE(dropped.cancelled) << "the request must end with its connection, not as delivered";
    EXPECT_LT(dropped.streamed, kHuge) << "the whole file was read into a session that queued none of it";
    c.read_until([] { return false; }, 5s);
    EXPECT_TRUE(c.eof);
    const auto next = exchange(server->port(), request("/static/small.txt", "after-drop"));
    EXPECT_EQ(next.response.body, small);
}

TEST_F(StaticFilesStreamTest, AHookThatEndsTheRequestLeavesTheFileUnstreamedAndTheServerServing) {
    auto server = serve(options(), [](Router &router) {
        add_pre_send_hook(router, [](qb::http::Context<FileSession> &c) {
            if (c.request().uri().path() == "/static/big.bin")
                c.cancel("refused by a hook");
        });
    });
    ASSERT_TRUE(server->ready());
    RawClient c;
    ASSERT_TRUE(c.connect(server->port()));
    ASSERT_TRUE(c.send(request("/static/big.bin", "ended")));
    // The cancellation's 503 carries no body, so it declares none: the length of the file it no longer serves would
    // leave the client waiting for bytes that never come, and read the next answer as them.
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer.substr(0, 512);
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.status, 503) << r.head;
    EXPECT_EQ(r.field("content-length"), "0") << r.head;
    EXPECT_FALSE(r.has("cache-control")) << "a shared cache may not keep the 503 for the file's lifetime: " << r.head;
    EXPECT_FALSE(r.has("etag")) << "a validator would let a cache refresh a stored 503 with the file's: " << r.head;
    EXPECT_FALSE(r.has("last-modified")) << r.head;
    EXPECT_FALSE(r.has("content-type")) << "no body, no type: " << r.head;
    ASSERT_TRUE(wait_for([] { return record_of("ended").has_value(); })) << "the request never ended";
    EXPECT_TRUE(record_of("ended")->cancelled);
    EXPECT_FALSE(record_of("ended")->streaming) << "begin_stream() refused a request a hook ended: nothing streams";
    c.buffer.erase(0, r.consumed);
    ASSERT_TRUE(c.send(request("/static/mid.bin", "after-end")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << "the connection must serve on";
    EXPECT_TRUE(parse_response(c.buffer).body == mid);
}

#ifdef QB_HAS_COMPRESSION
// The trade-off, pinned: a streamed body passes PRE_RESPONSE_SEND empty, so CompressionMiddleware leaves it alone; a
// body read whole is compressed as before.
TEST_F(StaticFilesStreamTest, CompressionLeavesAStreamedBodyAloneAndStillCompressesOneReadWhole) {
    const std::string text_small(kThreshold / 2, 'a');
    std::string       text_large;
    while (text_large.size() < 2 * kThreshold)
        text_large += "a line of compressible text for the static files suite\n";
    write_file("small.txt", text_small);
    write_file("large.txt", text_large);
    auto server = serve(options(), [](Router &router) {
        auto compression = std::make_shared<qb::http::CompressionMiddleware<FileSession>>();
        compression->update_options(
            qb::http::CompressionOptions().compress_responses(true).min_size_to_compress(512).preferred_encodings({"gzip"}));
        router.use(compression);
    });
    ASSERT_TRUE(server->ready());
    const auto whole = exchange(server->port(), request("/static/small.txt", "gz-small", "Accept-Encoding: gzip\r\n"));
    EXPECT_EQ(whole.response.field("content-encoding"), "gzip") << whole.response.head;
    EXPECT_LT(whole.response.body.size(), text_small.size());
    const auto streamed = exchange(server->port(), request("/static/large.txt", "gz-large", "Accept-Encoding: gzip\r\n"));
    EXPECT_FALSE(streamed.response.has("content-encoding")) << streamed.response.head;
    EXPECT_TRUE(streamed.response.body == text_large);
    ASSERT_TRUE(wait_for([] { return record_of("gz-large").has_value(); }));
    EXPECT_TRUE(record_of("gz-large")->streaming);
}
#endif // QB_HAS_COMPRESSION

#ifdef QB_HAS_SSL
// ------------------------------------------------------------------------------------------------ over TLS
namespace static_files_stream_test {
using SecureServer  = qb::http::ssl::Server<>;
using SecureSession = qb::http::ssl::DefaultSecureSession;
using TlsClient     = BasicRawClient<qb::io::tcp::ssl::socket>;
} // namespace static_files_stream_test

TEST_F(StaticFilesStreamTest, OverTlsABodyOverTheThresholdStreamsEveryByte) {
    qb::http::test::tls_identity identity{"qbm-static-files-stream"};
    ASSERT_TRUE(identity.ok());
    const auto opts   = options();
    auto       server = std::make_unique<ServerThread<SecureServer>>([&identity, opts](SecureServer &s) {
        s.router().add_observer(std::make_shared<Recorder<SecureSession>>());
        s.router().use(qb::http::static_files_middleware<SecureSession>(opts));
        s.router().compile();
        return s.listen(qb::io::uri{"tcp://127.0.0.1:0"}, identity.context());
    });
    ASSERT_TRUE(server->ready());
    const auto r = exchange<TlsClient>(server->port(), request("/static/big.bin", "tls"));
    ASSERT_TRUE(r.response.complete) << r.response.head;
    EXPECT_EQ(r.response.status, 200);
    EXPECT_TRUE(r.response.body == big) << "the bytes streamed over TLS differ from the file's";
    ASSERT_TRUE(wait_for([] { return record_of("tls").has_value(); }));
    EXPECT_TRUE(record_of("tls")->streaming);
    EXPECT_EQ(record_of("tls")->streamed, kBig);
}
#endif // QB_HAS_SSL

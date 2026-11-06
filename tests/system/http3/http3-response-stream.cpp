/**
 * @file qbm/http/tests/system/http3/http3-response-stream.cpp
 * @brief `Context::begin_stream()` / `ResponseStream` on HTTP/3 (Huly QB-86): the nghttp3 adapter driven directly,
 *        then the real server and client over QUIC loopback.
 *
 * Part 1 drives `qb::protocol::http3::connection<Owner>` with no socket, as `http3-connection-direct.cpp` does: a
 * server-role and a client-role connection, each backed by an owner that records the bytes nghttp3 asks it to send,
 * pumped into each other. It proves the adapter's streamed response on the frames it hands the transport: the header
 * section leaves at `begin_streamed_response()`; a piece written leaves (fin=false) BEFORE the end; nothing leaves
 * with nothing written (the data reader answers WOULDBLOCK) and a write resumes the stream; `end_streamed_response()`
 * ends the stream (fin), after the trailer section when there is one; the peer's acknowledgements bring
 * `streamed_body_pending()` down and reach the owner's three-argument `on_http3_stream_acked`; an abandoned response
 * hands nothing more out; a forbidden trailer field refuses the end.
 *
 * Part 2 runs `qb::http3::Server` and `qb::http3::Client` on one loop over QUIC loopback: the body arrives whole in
 * order and `end_of_stream` framed; the peer's acknowledgements prove the pieces arrived BEFORE `end()` (the stream's
 * `pending()` falls to 0 while it is open); HEAD gets its head alone; an application `cancel()` and an `abort()`
 * reset the stream -- the client reads 502 -- and the connection serves the next request; a declared length is
 * enforced; trailers set at the end reach the client; the client leaving cancels the stream.
 *
 * Gated on `QBM_HTTP_HAS_HTTP3`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <qbm/http/http.h>
#include <qbm/http/middleware/static_files.h>

#if defined(QBM_HTTP_HAS_HTTP3)

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <qb/io/async/quic/endpoint.h>
#include <qb/system/container/unordered_map.h>
#include <qb/uuid.h>

#include <filesystem>
#include <fstream>
#include <iostream>

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

using namespace std::chrono_literals;

namespace http3_response_stream_test {

// =============================================================================================== part 1: the adapter
using qb::protocol::http3::connection;

struct frame {
    std::uint64_t stream_id;
    std::string   data;
    bool          fin;
};

struct DirectOwnerBase {
    bool                                                 server_role = false;
    std::uint64_t                                        next_uni    = 0;
    std::deque<frame>                                    outbound;
    qb::unordered_map<std::uint64_t, std::uint64_t>      credit;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> resets;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> stops;
    std::optional<std::pair<std::uint64_t, std::string>> close;
    std::vector<std::uint64_t>                           drained;
    std::vector<std::uint64_t>                           shutdowns;

    std::uint64_t
    open_http3_unidirectional_stream(std::uint64_t) {
        const auto id = next_uni;
        next_uni += 4;
        return id;
    }
    void
    send_http3_stream_data(std::uint64_t, std::uint64_t stream_id, std::string_view data, bool fin) {
        outbound.push_back({stream_id, std::string(data), fin});
    }
    void
    extend_http3_stream_credit(std::uint64_t, std::uint64_t stream_id, std::uint64_t bytes) {
        credit[stream_id] += bytes;
    }
    void
    reset_http3_stream(std::uint64_t, std::uint64_t stream_id, std::uint64_t code) {
        resets.emplace_back(stream_id, code);
    }
    void
    stop_http3_stream(std::uint64_t, std::uint64_t stream_id, std::uint64_t code) {
        stops.emplace_back(stream_id, code);
    }
    void
    close_http3_connection(std::uint64_t, std::uint64_t code, std::string_view reason) {
        if (!close)
            close = std::make_pair(code, std::string(reason));
    }
    void
    on_http3_stream_output_drained(std::uint64_t, std::uint64_t stream_id) {
        drained.push_back(stream_id);
    }
    void
    on_http3_shutdown(std::uint64_t, std::uint64_t last_id) {
        shutdowns.push_back(last_id);
    }
};

/// The server owner takes the three-argument acknowledgement hook, as the HTTP/3 server does (Huly QB-86).
struct ServerOwner : DirectOwnerBase {
    std::vector<qb::http::Request>                                       requests;
    std::vector<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>> acks; ///< (connection, stream, bytes)

    ServerOwner() {
        server_role = true;
        next_uni    = 3;
    }
    void
    on_http3_request(std::uint64_t, std::uint64_t, qb::http::Request request) {
        requests.push_back(std::move(request));
    }
    void
    on_http3_stream_closed(std::uint64_t, std::uint64_t, std::uint64_t) {}
    void
    on_http3_stream_acked(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t bytes) {
        acks.emplace_back(connection_id, stream_id, bytes);
    }
};

/// The client owner keeps the two-argument hook: the adapter serves both shapes.
struct ClientOwner : DirectOwnerBase {
    std::vector<qb::http::Response>                      responses;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> acks;

    ClientOwner() {
        server_role = false;
        next_uni    = 2;
    }
    void
    on_http3_response(std::uint64_t, qb::http::Response response) {
        responses.push_back(std::move(response));
    }
    void
    on_http3_stream_closed(std::uint64_t, std::uint64_t) {}
    void
    on_http3_stream_acked(std::uint64_t stream_id, std::uint64_t bytes) {
        acks.emplace_back(stream_id, bytes);
    }
};

using ServerConnection = connection<ServerOwner>;
using ClientConnection = connection<ClientOwner>;

template <typename FromOwner, typename ToConn>
std::size_t
deliver(FromOwner &from_owner, ToConn &to_conn) {
    std::size_t moved = 0;
    auto        queue = std::move(from_owner.outbound);
    from_owner.outbound.clear();
    for (auto &f : queue) {
        ++moved;
        to_conn.read_stream(f.stream_id, f.data, f.fin);
    }
    return moved;
}

struct Pair {
    ClientOwner      client_owner;
    ServerOwner      server_owner;
    ClientConnection client{client_owner, 1, ClientConnection::role::client};
    ServerConnection server{server_owner, 7, ServerConnection::role::server};

    Pair() {
        EXPECT_TRUE(client.ok());
        EXPECT_TRUE(server.ok());
        EXPECT_TRUE(client.bind_local_streams());
        EXPECT_TRUE(server.bind_local_streams());
        settle();
    }

    void
    settle() {
        for (int i = 0; i < 64; ++i) {
            const auto a = deliver(client_owner, server);
            const auto b = deliver(server_owner, client);
            if (a == 0 && b == 0)
                return;
        }
    }

    /// The frames the server handed its transport for `stream_id` since the last call: (payload bytes, a fin).
    std::pair<std::size_t, bool>
    server_sent(std::uint64_t stream_id) {
        std::size_t bytes = 0;
        bool        fin   = false;
        for (auto const &f : server_owner.outbound)
            if (f.stream_id == stream_id) {
                bytes += f.data.size();
                fin = fin || f.fin;
            }
        return {bytes, fin};
    }

    /// A GET on stream 0, dispatched to the server owner.
    void
    get(std::string const &path = "/stream") {
        qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test" + path)};
        EXPECT_TRUE(client.submit_request(0, request));
        settle();
        EXPECT_EQ(server_owner.requests.size(), 1u);
    }
};

qb::http::Response
ok_response() {
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("content-type", "text/plain");
    return response;
}

TEST(Http3ResponseStreamDirect, TheHeadLeavesAtOnceAndAPieceLeavesBeforeTheEnd) {
    Pair pair;
    pair.get();
    ASSERT_TRUE(pair.server.begin_streamed_response(0, ok_response()));
    EXPECT_TRUE(pair.server.is_streaming_response(0));
    auto [head_bytes, head_fin] = pair.server_sent(0);
    EXPECT_GT(head_bytes, 0u) << "the header section is on its way";
    EXPECT_FALSE(head_fin);
    pair.settle();
    EXPECT_TRUE(pair.client_owner.responses.empty()) << "the client has the head, not the message: no fin yet";

    ASSERT_TRUE(pair.server.write_streamed_body(0, "piece-one;"));
    auto [piece_bytes, piece_fin] = pair.server_sent(0);
    EXPECT_GE(piece_bytes, std::string("piece-one;").size()) << "the piece left as a DATA frame before any end";
    EXPECT_FALSE(piece_fin);
    EXPECT_EQ(pair.server.streamed_body_pending(0), std::string("piece-one;").size()) << "written, not acknowledged";
    pair.settle();
    EXPECT_TRUE(pair.client_owner.responses.empty());

    ASSERT_TRUE(pair.server.write_streamed_body(0, "piece-two;"));
    ASSERT_TRUE(pair.server.end_streamed_response(0, nullptr));
    auto [end_bytes, end_fin] = pair.server_sent(0);
    EXPECT_TRUE(end_fin) << "end_streamed_response() ends the stream";
    pair.settle();
    ASSERT_EQ(pair.client_owner.responses.size(), 1u);
    EXPECT_EQ(pair.client_owner.responses.front().status(), qb::http::status::OK);
    EXPECT_EQ(pair.client_owner.responses.front().body().template as<std::string>(), "piece-one;piece-two;");
    EXPECT_TRUE(pair.client_owner.responses.front().header("content-length").empty());
    EXPECT_FALSE(pair.server.is_streaming_response(0));
    EXPECT_FALSE(pair.server_owner.close.has_value());
    EXPECT_FALSE(pair.client_owner.close.has_value());
}

TEST(Http3ResponseStreamDirect, NothingLeavesWithNothingWrittenAndAWriteResumesTheStream) {
    Pair pair;
    pair.get();
    ASSERT_TRUE(pair.server.begin_streamed_response(0, ok_response()));
    pair.settle();
    pair.server_owner.outbound.clear();
    // A drain with nothing written: the data reader answered WOULDBLOCK, the stream is suspended.
    ASSERT_TRUE(pair.server.write_streamed_body(0, {})); // an empty piece changes nothing
    EXPECT_EQ(pair.server_sent(0).first, 0u);
    ASSERT_TRUE(pair.server.write_streamed_body(0, "resumed"));
    EXPECT_GE(pair.server_sent(0).first, 7u) << "the write resumed the stream and its bytes left";
    ASSERT_TRUE(pair.server.end_streamed_response(0, nullptr));
    pair.settle();
    ASSERT_EQ(pair.client_owner.responses.size(), 1u);
    EXPECT_EQ(pair.client_owner.responses.front().body().template as<std::string>(), "resumed");
}

TEST(Http3ResponseStreamDirect, AcknowledgementsBringPendingDownAndReachTheOwner) {
    Pair pair;
    pair.get();
    ASSERT_TRUE(pair.server.begin_streamed_response(0, ok_response()));
    ASSERT_TRUE(pair.server.write_streamed_body(0, std::string(1000, 'a')));
    ASSERT_TRUE(pair.server.write_streamed_body(0, std::string(500, 'b')));
    EXPECT_EQ(pair.server.streamed_body_pending(0), 1500u);
    // The transport reports what the peer acknowledged: the header section's bytes first, then the body's.
    std::size_t sent = 0;
    for (auto const &f : pair.server_owner.outbound)
        if (f.stream_id == 0)
            sent += f.data.size();
    ASSERT_GE(sent, 1500u);
    pair.server.add_ack_offset(0, sent - 1500 + 1000); // the head and the first piece
    EXPECT_EQ(pair.server.streamed_body_pending(0), 500u) << "the first piece is acknowledged";
    ASSERT_FALSE(pair.server_owner.acks.empty());
    EXPECT_EQ(std::get<0>(pair.server_owner.acks.back()), 7u) << "the connection id, through the three-argument hook";
    EXPECT_EQ(std::get<1>(pair.server_owner.acks.back()), 0u);
    pair.server.add_ack_offset(0, 500);
    EXPECT_EQ(pair.server.streamed_body_pending(0), 0u);
    ASSERT_TRUE(pair.server.end_streamed_response(0, nullptr));
    pair.settle();
    ASSERT_EQ(pair.client_owner.responses.size(), 1u);
    EXPECT_EQ(pair.client_owner.responses.front().body().size(), 1500u);
}

TEST(Http3ResponseStreamDirect, TrailersSetAtTheEndReachTheClientAfterTheBody) {
    Pair pair;
    pair.get();
    ASSERT_TRUE(pair.server.begin_streamed_response(0, ok_response()));
    ASSERT_TRUE(pair.server.write_streamed_body(0, "body"));
    auto final_response = ok_response();
    final_response.trailers().set_header("x-checksum", "cafe");
    ASSERT_TRUE(pair.server.end_streamed_response(0, &final_response));
    pair.settle();
    ASSERT_EQ(pair.client_owner.responses.size(), 1u);
    auto const &received = pair.client_owner.responses.front();
    EXPECT_EQ(received.body().template as<std::string>(), "body");
    EXPECT_EQ(received.trailers().header("x-checksum"), "cafe");
}

TEST(Http3ResponseStreamDirect, AForbiddenTrailerFieldRefusesTheEnd) {
    Pair pair;
    pair.get();
    ASSERT_TRUE(pair.server.begin_streamed_response(0, ok_response()));
    auto final_response = ok_response();
    final_response.trailers().set_header("content-length", "4");
    EXPECT_FALSE(pair.server.end_streamed_response(0, &final_response)) << "the caller resets the stream";
    EXPECT_FALSE(pair.server.is_streaming_response(0)) << "the refusal ended the stream for the producer, as an abandon does";
    EXPECT_FALSE(pair.server.write_streamed_body(0, "late")) << "nothing more is handed out on a stream the caller resets";
    EXPECT_FALSE(pair.server.end_streamed_response(0, nullptr));
}

TEST(Http3ResponseStreamDirect, AnAbandonedResponseHandsNothingMoreOut) {
    Pair pair;
    pair.get();
    ASSERT_TRUE(pair.server.begin_streamed_response(0, ok_response()));
    ASSERT_TRUE(pair.server.write_streamed_body(0, "first"));
    pair.settle();
    pair.server_owner.outbound.clear();
    EXPECT_TRUE(pair.server.abandon_streamed_response(0));
    EXPECT_FALSE(pair.server.is_streaming_response(0));
    EXPECT_FALSE(pair.server.write_streamed_body(0, "late"));
    EXPECT_FALSE(pair.server.end_streamed_response(0, nullptr));
    EXPECT_FALSE(pair.server.abandon_streamed_response(0)) << "once";
    pair.settle();
    EXPECT_EQ(pair.server_sent(0).first, 0u) << "nothing of the stream leaves after it was abandoned";
    EXPECT_TRUE(pair.client_owner.responses.empty());
}

TEST(Http3ResponseStreamDirect, ASecondResponseOnTheStreamIsRefused) {
    Pair pair;
    pair.get();
    ASSERT_TRUE(pair.server.begin_streamed_response(0, ok_response()));
    EXPECT_FALSE(pair.server.begin_streamed_response(0, ok_response()));
    EXPECT_FALSE(pair.server.submit_response(0, ok_response()));
    auto malformed = ok_response();
    malformed.set_header("content-length", "not-a-number");
    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/second")};
    ASSERT_TRUE(pair.client.submit_request(4, request));
    pair.settle();
    EXPECT_FALSE(pair.server.begin_streamed_response(4, malformed)) << "a malformed content-length refuses the head";
}

// =============================================================================================== part 2: QUIC loopback
using H3Session = qb::http3::DefaultSession;
using H3Ctx     = qb::http::Context<H3Session>;
using H3Stream  = qb::http::ResponseStream<H3Session>;

static_assert(qb::http::streaming_session<H3Session>, "the HTTP/3 session streams (Huly QB-86)");

/// What the handlers leave for the test: everything runs on the one loop, so plain values do.
struct Loopback {
    std::shared_ptr<H3Stream> stream; ///< the stream a handler handed to the test
    int                       framing             = -1;
    bool                      closed_seen         = false;
    std::size_t               written_at_close    = 0;
    bool                      drain_verdict_false = false;
    int                       forbidden_outcome   = 0; ///< /trailers-forbidden at REQUEST_COMPLETE: 1 cancelled, 2 completed
    // What the router's observer read when the static download ended (Huly QB-1212).
    bool        responded_seen      = false;
    bool        responded_cancelled = false;
    std::size_t responded_streamed  = 0;
};
inline Loopback              g;
inline std::filesystem::path g_static_root; ///< a directory with big.bin: the static files are mounted when set (Huly QB-1212)

/// The observer the static files' deadline case reads: cancelled or not, and the bytes streamed, at the end of /static/big.bin.
struct Observer : qb::http::IRequestObserver<H3Session> {
    void
    on_response(H3Ctx const &ctx, qb::http::RequestEnd const &) noexcept override {
        if (ctx.request().uri().path() != "/static/big.bin")
            return;
        g.responded_seen      = true;
        g.responded_cancelled = ctx.is_cancelled();
        g.responded_streamed  = ctx.streamed_bytes();
    }
};

/// A bare QUIC peer speaking just enough HTTP/3 to ask for one file and then take no more of it than its 16 KiB
/// stream window: it never returns credit, so the server's stream stalls at the window exactly as it does behind a
/// client that stopped reading. A second request on a new stream shows the connection served on (Huly QB-1212).
class StallingH3Peer : public qb::io::async::quic::endpoint {
    std::uint16_t _port;

    static qb::io::quic::settings
    window() {
        qb::io::quic::settings s;
        s.stream_recv_window          = 16 * 1024;
        s.connection_recv_window      = 64 * 1024;
        s.max_stream_data_bidi_local  = 16 * 1024;
        s.max_stream_data_bidi_remote = 16 * 1024;
        s.max_stream_data_uni         = 16 * 1024;
        return s;
    }
    static bool
    read_varint(std::string const &bytes, std::size_t &at, std::uint64_t &value) {
        if (at >= bytes.size())
            return false;
        const auto        first  = static_cast<std::uint8_t>(bytes[at]);
        const std::size_t length = std::size_t{1} << (first >> 6);
        if (at + length > bytes.size())
            return false;
        value = first & 0x3Fu;
        for (std::size_t i = 1; i < length; ++i)
            value = (value << 8) | static_cast<std::uint8_t>(bytes[at + i]);
        at += length;
        return true;
    }
    static void
    varint(std::string &out, std::uint64_t v) {
        if (v < 64) {
            out.push_back(static_cast<char>(v));
        } else if (v < 16384) {
            out.push_back(static_cast<char>(0x40 | (v >> 8)));
            out.push_back(static_cast<char>(v & 0xFF));
        } else {
            out.push_back(static_cast<char>(0x80 | (v >> 24)));
            out.push_back(static_cast<char>((v >> 16) & 0xFF));
            out.push_back(static_cast<char>((v >> 8) & 0xFF));
            out.push_back(static_cast<char>(v & 0xFF));
        }
    }
    /// A QPACK literal field line whose name is a static-table entry (RFC 9204 section 4.5.4), value under 127 bytes, not Huffman-coded.
    static void
    literal(std::string &out, std::uint8_t static_index, std::string_view value) {
        out.push_back(static_cast<char>(0x50 | static_index));
        out.push_back(static_cast<char>(value.size()));
        out.append(value);
    }
    /// A HEADERS frame asking GET `path`: the static table alone (:method GET = 17, :scheme https = 23, :authority = 0, :path = 1).
    std::string
    request_frame(std::string_view path) const {
        std::string block;
        block.append("\x00\x00", 2); // required insert count 0, base 0: no dynamic table
        block.push_back(static_cast<char>(0xD1));
        block.push_back(static_cast<char>(0xD7));
        literal(block, 0, "127.0.0.1:" + std::to_string(_port));
        literal(block, 1, path);
        std::string frame;
        varint(frame, 0x01);
        varint(frame, block.size());
        return frame + block;
    }

protected:
    void
    dispatch(qb::io::async::quic::event::connected const &) override {
        connected = true;
        send_stream_data(open_unidirectional_stream().id(), std::string("\x00\x04\x00", 3)); // control stream: an empty SETTINGS
        send_stream_data(open_unidirectional_stream().id(), std::string("\x02", 1));         // QPACK encoder stream
        send_stream_data(open_unidirectional_stream().id(), std::string("\x03", 1));         // QPACK decoder stream
        first = open_bidirectional_stream().id();
        send_stream_data(first, request_frame("/static/big.bin"), true);
    }
    void
    dispatch(qb::io::async::quic::event::stream_data const &ev) override {
        if (ev.id == first) {
            connection = ev.connection_id;
            first_bytes += ev.payload.size(); // not credited back here: the window is all this peer takes unless the test credits it
            if (ev.fin)
                first_fin = true;
        } else if (ev.id == second) {
            second_payload.append(ev.payload.data(), ev.payload.size());
            if (ev.fin)
                second_fin = true;
            extend_stream_credit(ev.connection_id, ev.id, ev.payload.size());
        }
    }
    void
    dispatch(qb::io::async::quic::event::stream_closed const &ev) override {
        if (ev.id == first && ev.reason != qb::io::quic::stream_close_reason::finished) {
            first_reset        = true;
            first_reset_reason = ev.reason;
            first_reset_code   = ev.error_code;
        }
    }
    void
    dispatch(qb::io::async::quic::event::connection_closed const &) override {
        connection_closed = true;
    }

public:
    bool                              connected          = false;
    bool                              connection_closed  = false;
    std::uint64_t                     first              = ~std::uint64_t{0}; ///< the stalled download's stream
    std::size_t                       first_bytes        = 0;
    bool                              first_reset        = false;
    std::uint64_t                     first_reset_code   = 0;
    std::uint64_t                     connection         = 0;
    bool                              first_fin          = false;
    qb::io::quic::stream_close_reason first_reset_reason = qb::io::quic::stream_close_reason::none;
    std::uint64_t                     second             = ~std::uint64_t{0}; ///< the request made once the first was cut
    std::string                       second_payload;
    bool                              second_fin = false;

    explicit StallingH3Peer(std::uint16_t port)
        : endpoint(window())
        , _port(port) {}

    bool
    open() {
        qb::io::quic::tls_config tls;
        tls.verify_peer = false;
        return connect(qb::io::uri("https://127.0.0.1:" + std::to_string(_port)), tls, {"h3"});
    }
    /// The test's hand on the window: `bytes` more of the first stream may come.
    void
    credit(std::size_t bytes) {
        extend_stream_credit(connection, first, bytes);
    }
    void
    ask_again(std::string_view path) {
        second = open_bidirectional_stream().id();
        send_stream_data(second, request_frame(path), true);
    }
    /// 200 when the second response's HEADERS frame opens, after a prefix of no dynamic table (0x00 0x00), with the
    /// static table's `:status: 200` indexed (entry 25, 0xD9, RFC 9204 Appendix A); 0 when the frame is not there or the
    /// server encoded its status another way.
    [[nodiscard]] int
    second_status() const {
        std::size_t   at   = 0;
        std::uint64_t type = 0, length = 0;
        if (!read_varint(second_payload, at, type) || type != 0x01 || !read_varint(second_payload, at, length)
            || at + 3 > second_payload.size())
            return 0;
        if (second_payload[at] != 0 || second_payload[at + 1] != 0)
            return 0;
        return static_cast<std::uint8_t>(second_payload[at + 2]) == 0xD9 ? 200 : 0;
    }
};

/// A directory holding big.bin, 4 MiB of pseudo-random bytes, removed with its scope; `ok` says the file was written.
struct StaticRoot {
    std::filesystem::path path;
    bool                  ok = false;
    StaticRoot() {
        path = std::filesystem::temp_directory_path() / ("qbm-h3-deadline-" + uuids::to_string(qb::generate_random_uuid()));
        std::filesystem::create_directories(path);
        std::string   big(std::size_t{4} * 1024 * 1024, '\0');
        std::uint32_t x = 11u;
        for (auto &ch : big) {
            x  = x * 1664525u + 1013904223u;
            ch = static_cast<char>(x >> 24);
        }
        std::ofstream out(path / "big.bin", std::ios::binary);
        out.write(big.data(), static_cast<std::streamsize>(big.size()));
        out.close();
        ok            = out.good();
        g_static_root = path;
    }
    ~StaticRoot() {
        g_static_root.clear();
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

class Http3ResponseStreamTest : public ::testing::Test {
protected:
    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available()) << "the HTTP/3 system tests need the TLS test certificates";
        qb::io::async::init();
        g = Loopback{};
    }

    static std::string
    origin(std::uint16_t port) {
        return "https://127.0.0.1:" + std::to_string(port);
    }

    static bool
    pump(std::function<bool()> const &done, std::chrono::milliseconds budget = 5s) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (!done()) {
            if (std::chrono::steady_clock::now() >= deadline) {
                ADD_FAILURE() << "pump: predicate not satisfied within " << budget.count() << "ms";
                return false;
            }
            if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT))
                std::this_thread::sleep_for(1ms);
        }
        return true;
    }

    /// The loop run for `window`, whatever happens in it.
    static void
    pump_for(std::chrono::milliseconds window) {
        const auto until = std::chrono::steady_clock::now() + window;
        while (std::chrono::steady_clock::now() < until)
            if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT))
                std::this_thread::sleep_for(1ms);
    }

    /// A server with the routes of this suite, listening on `port`.
    static std::unique_ptr<qb::http3::Server<>>
    make_server(std::uint16_t port) {
        auto  server = qb::http3::make_server();
        auto &r      = server->router();
        r.get("/pieces", [](std::shared_ptr<H3Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("content-type", "text/plain");
            g.stream  = ctx->begin_stream();
            g.framing = static_cast<int>(g.stream->framing());
            (void) g.stream->write("piece-0;");
            (void) g.stream->write("piece-1;");
            // The test ends the stream once it saw the pieces acknowledged by the peer.
        });
        r.head("/pieces", [](std::shared_ptr<H3Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            (void) stream->write("counted-not-sent");
            stream->end();
        });
        r.get("/cancel", [](std::shared_ptr<H3Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            (void) stream->write("never whole");
            ctx->cancel("cancelled before the end");
        });
        r.get("/abort", [](std::shared_ptr<H3Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("content-length", "64");
            auto stream = ctx->begin_stream();
            (void) stream->write("never whole");
            stream->end(); // short of 64: aborted
        });
        r.get("/declared", [](std::shared_ptr<H3Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("content-length", "16");
            auto stream = ctx->begin_stream();
            g.framing   = static_cast<int>(stream->framing());
            (void) stream->write("12345678");
            qb::io::async::callback(
                [stream] {
                    (void) stream->write("abcdefgh");
                    stream->end();
                },
                2ms);
        });
        r.get("/trailers", [](std::shared_ptr<H3Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            (void) stream->write("first;");
            qb::io::async::callback(
                [stream, ctx] {
                    (void) stream->write("second;");
                    ctx->response().trailers().set_header("x-checksum", "beef");
                    stream->end();
                },
                2ms);
        });
        r.get("/trailers-forbidden", [](std::shared_ptr<H3Ctx> ctx) {
            // A trailer section the stream cannot carry at end(): the stream is reset and the context CANCELLED, as
            // HTTP/2's RST_STREAM cancels it -- never completed as if the response had gone whole.
            ctx->add_lifecycle_hook([](H3Ctx &c, qb::http::HookPoint point) {
                if (point == qb::http::HookPoint::REQUEST_COMPLETE)
                    g.forbidden_outcome = c.is_cancelled() ? 1 : 2;
            });
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            (void) stream->write("first;");
            ctx->response().trailers().set_header("content-length", "6"); // a field a trailer section must not carry
            stream->end();
        });
        r.get("/forever", [](std::shared_ptr<H3Ctx> ctx) -> qb::io::async::task<void> {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            g.stream                 = stream;
            stream->set_watermarks(16, 8);
            for (int i = 0; i < 100000; ++i) {
                const auto verdict = stream->write("tick;");
                if (verdict == H3Stream::write_result::closed) {
                    g.closed_seen      = true;
                    g.written_at_close = stream->written();
                    co_return;
                }
                if (stream->needs_drain() && !co_await stream->drain()) {
                    g.drain_verdict_false = true;
                    co_return;
                }
            }
            stream->end();
        });
        r.get("/plain", [](std::shared_ptr<H3Ctx> ctx) { ctx->text("still served"); });
        r.add_observer(std::make_shared<Observer>());
        if (!g_static_root.empty()) // /static/big.bin streams, and a peer that stops taking bytes is cut at 500 ms (Huly QB-1212)
            r.use(qb::http::static_files_middleware<H3Session>(qb::http::StaticFilesOptions(g_static_root)
                                                                   .with_path_prefix_to_strip("/static")
                                                                   .with_stream_threshold(std::size_t{64} * 1024)
                                                                   .with_stream_idle_deadline(500ms)));
        r.compile();
        EXPECT_TRUE(server->listen(qb::io::uri(origin(port)), qb::http::test::ssl_cert_path(), qb::http::test::ssl_key_path()));
        return server;
    }

    static std::shared_ptr<qb::http3::Client>
    make_client(std::uint16_t port) {
        auto client = qb::http3::make_client(origin(port));
        client->set_verify_peer(false);
        return client;
    }

    /// One request; the response once it came.
    static std::optional<qb::http::Response>
    get(std::shared_ptr<qb::http3::Client> const &client, std::uint16_t port, std::string const &path, std::string const &method = "GET",
        std::chrono::milliseconds budget = 5s) {
        std::optional<qb::http::Response> response;
        qb::http::Request                 request{qb::io::uri(origin(port) + path)};
        request.method() = qb::http::Method(method);
        EXPECT_TRUE(client->push_request(std::move(request), [&](qb::http::Response r) { response = std::move(r); }));
        pump([&] { return response.has_value(); }, budget);
        return response;
    }
};

TEST_F(Http3ResponseStreamTest, PiecesAreAcknowledgedByThePeerBeforeTheStreamEnds) {
    const auto                        port   = qb::http::test::ephemeral_udp_port();
    auto                              server = make_server(port);
    auto                              client = make_client(port);
    std::optional<qb::http::Response> response;
    EXPECT_TRUE(
        client->push_request(qb::http::Request{qb::io::uri(origin(port) + "/pieces")}, [&](qb::http::Response r) { response = std::move(r); }));
    ASSERT_TRUE(pump([&] { return g.stream && g.stream->pending() == 0 && g.stream->written() == 16; }))
        << "the peer acknowledged both pieces while the stream is still open";
    EXPECT_FALSE(response.has_value()) << "the client has no message yet: the stream has not ended";
    EXPECT_EQ(g.framing, static_cast<int>(qb::http::stream_framing::end_of_stream));
    g.stream->end();
    g.stream.reset();
    ASSERT_TRUE(pump([&] { return response.has_value(); }));
    EXPECT_EQ(response->status(), qb::http::status::OK);
    EXPECT_EQ(response->body().template as<std::string>(), "piece-0;piece-1;");
    EXPECT_TRUE(response->header("content-length").empty());
    client->disconnect();
    server->close();
}

TEST_F(Http3ResponseStreamTest, HeadGetsTheHeadAlone) {
    const auto port     = qb::http::test::ephemeral_udp_port();
    auto       server   = make_server(port);
    auto       client   = make_client(port);
    const auto response = get(client, port, "/pieces", "HEAD");
    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response->status(), qb::http::status::OK);
    EXPECT_TRUE(response->body().empty());
    const auto next = get(client, port, "/plain");
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(next->body().template as<std::string>(), "still served");
    client->disconnect();
    server->close();
}

TEST_F(Http3ResponseStreamTest, ACancelledStreamResetsTheStreamAndTheConnectionServesOn) {
    const auto port      = qb::http::test::ephemeral_udp_port();
    auto       server    = make_server(port);
    auto       client    = make_client(port);
    const auto cancelled = get(client, port, "/cancel");
    ASSERT_TRUE(cancelled.has_value());
    EXPECT_EQ(cancelled->status(), qb::http::status::BAD_GATEWAY) << "the head left, the stream was reset";
    const auto next = get(client, port, "/plain");
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(next->status(), qb::http::status::OK) << "the connection serves on";
    client->disconnect();
    server->close();
}

TEST_F(Http3ResponseStreamTest, AnEndShortOfTheDeclaredLengthResetsTheStream) {
    const auto port    = qb::http::test::ephemeral_udp_port();
    auto       server  = make_server(port);
    auto       client  = make_client(port);
    const auto aborted = get(client, port, "/abort");
    ASSERT_TRUE(aborted.has_value());
    EXPECT_EQ(aborted->status(), qb::http::status::BAD_GATEWAY);
    const auto next = get(client, port, "/plain");
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(next->status(), qb::http::status::OK);
    client->disconnect();
    server->close();
}

TEST_F(Http3ResponseStreamTest, ADeclaredLengthStreamsIdentityWhole) {
    const auto port     = qb::http::test::ephemeral_udp_port();
    auto       server   = make_server(port);
    auto       client   = make_client(port);
    const auto response = get(client, port, "/declared");
    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(g.framing, static_cast<int>(qb::http::stream_framing::content_length));
    EXPECT_EQ(response->status(), qb::http::status::OK);
    EXPECT_EQ(response->header("content-length"), "16");
    EXPECT_EQ(response->body().template as<std::string>(), "12345678abcdefgh");
    client->disconnect();
    server->close();
}

TEST_F(Http3ResponseStreamTest, TrailersSetAtTheEndReachTheClient) {
    const auto port     = qb::http::test::ephemeral_udp_port();
    auto       server   = make_server(port);
    auto       client   = make_client(port);
    const auto response = get(client, port, "/trailers");
    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response->body().template as<std::string>(), "first;second;");
    EXPECT_EQ(response->trailers().header("x-checksum"), "beef");
    client->disconnect();
    server->close();
}

TEST_F(Http3ResponseStreamTest, ATrailerSectionTheStreamRefusesResetsItAndCancelsTheContext) {
    const auto port    = qb::http::test::ephemeral_udp_port();
    auto       server  = make_server(port);
    auto       client  = make_client(port);
    const auto refused = get(client, port, "/trailers-forbidden");
    ASSERT_TRUE(refused.has_value());
    EXPECT_EQ(refused->status(), qb::http::status::BAD_GATEWAY) << "the head left, the stream was reset at end()";
    EXPECT_EQ(g.forbidden_outcome, 1) << "the context was cancelled (2: completed as if the response had gone whole)";
    const auto next = get(client, port, "/plain");
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(next->status(), qb::http::status::OK) << "the connection serves on";
    client->disconnect();
    server->close();
}

TEST_F(Http3ResponseStreamTest, AStaticDownloadWhosePeerStopsTakingBytesIsResetAtTheIdleDeadline) {
    // The peer's 16 KiB stream window never grows: the server's stream stalls at it, nothing past it is acknowledged,
    // and the static files' idle deadline (500 ms here) aborts the stream -- RESET_STREAM H3_REQUEST_CANCELLED, the
    // context cancelled, the file released -- while the connection serves the next request (Huly QB-1212).
    const auto port = qb::http::test::ephemeral_udp_port();
    StaticRoot root;
    ASSERT_TRUE(root.ok) << "big.bin was not written under " << root.path;
    auto           server = make_server(port);
    StallingH3Peer peer(port);
    const auto     t0 = std::chrono::steady_clock::now();
    ASSERT_TRUE(peer.open());
    ASSERT_TRUE(pump([&] { return peer.connected; }));
    ASSERT_TRUE(pump([&] { return peer.first_bytes >= 16 * 1024; })) << "the window should fill: " << peer.first_bytes;
    const auto parked = std::chrono::steady_clock::now();
    ASSERT_TRUE(pump([&] { return peer.first_reset; }, 3s)) << "the stalled download was never cut";
    const auto now      = std::chrono::steady_clock::now();
    const auto cut      = std::chrono::duration_cast<std::chrono::milliseconds>(now - parked);
    const auto since_t0 = std::chrono::duration_cast<std::chrono::milliseconds>(now - t0);
    std::cout << "[  cut   ] HTTP/3 stalled download reset " << cut.count() << " ms after the window filled (deadline 500 ms)\n";
    EXPECT_GE(since_t0, 500ms) << "not before the deadline has passed since the request: " << since_t0.count() << " ms";
    EXPECT_LE(cut, 900ms) << "within the deadline and 400 ms of loop latency (twice it: a whole deadline re-armed): " << cut.count() << " ms";
    EXPECT_TRUE(peer.first_reset_reason == qb::io::quic::stream_close_reason::reset
                || peer.first_reset_reason == qb::io::quic::stream_close_reason::stop_sending)
        << "the server shut the stream down (RESET_STREAM and STOP_SENDING, either first): " << static_cast<int>(peer.first_reset_reason);
    EXPECT_EQ(peer.first_reset_code, 0x10Cu) << "H3_REQUEST_CANCELLED";
    EXPECT_LE(peer.first_bytes, std::size_t{16} * 1024) << "nothing past the window";
    EXPECT_FALSE(peer.connection_closed) << "the stream, never the connection";
    ASSERT_TRUE(pump([&] { return g.responded_seen; }));
    EXPECT_TRUE(g.responded_cancelled) << "the context was cancelled";
    EXPECT_LT(g.responded_streamed, std::size_t{4} * 1024 * 1024);
    peer.ask_again("/plain");
    ASSERT_TRUE(pump([&] { return peer.second_fin; })) << "the connection serves on";
    EXPECT_EQ(peer.second_status(), 200);
    EXPECT_NE(peer.second_payload.find("still served"), std::string::npos);
    peer.close();
    server->close();
}

TEST_F(Http3ResponseStreamTest, APeerThatCreditsItsWindowInBurstsFinishesUnderTheDeadline) {
    // The positive control of the HTTP/3 watch (Huly QB-1212): the same peer, crediting 256 KiB every 100 ms once its
    // first window filled -- the server's stream stalls at every window and is acknowledged again at every credit, for
    // 4 MiB over several deadlines -- gets the whole file and its FIN, never a reset.
    const auto port = qb::http::test::ephemeral_udp_port();
    StaticRoot root;
    ASSERT_TRUE(root.ok) << "big.bin was not written under " << root.path;
    auto           server = make_server(port);
    StallingH3Peer peer(port);
    const auto     started = std::chrono::steady_clock::now();
    ASSERT_TRUE(peer.open());
    ASSERT_TRUE(pump([&] { return peer.first_bytes >= 16 * 1024; }));
    int credits = 0;
    while (!peer.first_fin && !peer.first_reset && credits < 64) {
        pump_for(100ms);
        peer.credit(256 * 1024);
        ++credits;
        ASSERT_TRUE(pump(
            [&] { return peer.first_fin || peer.first_reset || peer.first_bytes >= 16 * 1024 + std::size_t{256} * 1024 * credits - 1024; }, 5s))
            << "credit " << credits << " brought nothing";
    }
    const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    EXPECT_FALSE(peer.first_reset) << "a peer that keeps crediting is not a stalled one";
    EXPECT_TRUE(peer.first_fin) << "the download never ended (" << credits << " credits, " << peer.first_bytes << " bytes)";
    EXPECT_GE(peer.first_bytes, std::size_t{4} * 1024 * 1024);
    EXPECT_GE(credits, 16);
    EXPECT_GT(took, 1s) << "several deadlines long: " << took.count() << " ms";
    EXPECT_FALSE(peer.connection_closed);
    ASSERT_TRUE(pump([&] { return g.responded_seen; }));
    EXPECT_FALSE(g.responded_cancelled);
    EXPECT_EQ(g.responded_streamed, std::size_t{4} * 1024 * 1024);
    peer.close();
    server->close();
}

TEST_F(Http3ResponseStreamTest, TheClientLeavingCancelsTheStream) {
    const auto                        port   = qb::http::test::ephemeral_udp_port();
    auto                              server = make_server(port);
    auto                              client = make_client(port);
    std::optional<qb::http::Response> response;
    EXPECT_TRUE(client->push_request(qb::http::Request{qb::io::uri(origin(port) + "/forever")},
                                     [&](qb::http::Response r) { response = std::move(r); }));
    ASSERT_TRUE(pump([&] { return g.stream && g.stream->written() >= 100; }));
    client->disconnect();
    ASSERT_TRUE(pump([&] { return g.closed_seen || g.drain_verdict_false; }))
        << "the producer was told: write answered closed, or the drain false";
    EXPECT_TRUE(g.stream->cancelled());
    EXPECT_EQ(g.stream->write("after"), H3Stream::write_result::closed);
    g.stream.reset();
    server->close();
}

} // namespace http3_response_stream_test

#else // !QBM_HTTP_HAS_HTTP3

TEST(Http3ResponseStream, SkippedWithoutHttp3) {
    GTEST_SKIP() << "HTTP/3 is not built: QBM_HTTP_HAS_HTTP3 is off";
}

#endif

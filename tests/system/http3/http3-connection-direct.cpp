/**
 * @file qbm/http/tests/system/http3/http3-connection-direct.cpp
 * @brief System tier: the HTTP/3 `connection<Owner>` adapter driven directly against a paired peer,
 *        with NO QUIC/TLS/socket — a deterministic in-process nghttp3 round-trip.
 *
 * `unit/http3/http3-validation.cpp` covers the pure `qb::protocol::http3::detail` field helpers, and
 * `system/http3/http3-loopback.cpp` covers the full `qb::http3::Server`/`Client` stack over a real
 * QUIC+TLS loopback. Neither drives `qb::protocol::http3::connection<Owner>` *directly*, so the
 * adapter's own engine-facing surface — `bind_local_streams`, `submit_request` / `submit_response`,
 * `read_stream`, `drain`, `add_ack_offset`, `shutdown` / `submit_shutdown_notice` — and, crucially, the
 * nghttp3 C-callback decode path it wires up (`recv_header_cb` -> `materialize_headers` ->
 * `end_stream_cb` -> `on_http3_request` / `on_http3_response`, `recv_data_cb`, the trailer callbacks,
 * `content_length_matches`, `stream_close_cb`, `acked_stream_data_cb`, `shutdown_cb`) were only reached
 * through the heavyweight TLS loopback and never in isolation.
 *
 * This file closes that gap with the SAME pattern the qb-io QUIC suite uses one layer down
 * (`deliver_quic_packets` pumping two native backends against each other in
 * `system/quic/quic-handshake.cpp`): two `connection<Owner>` objects — one server-role, one
 * client-role — each backed by a `DirectOwner` that simply BUFFERS the bytes nghttp3 asks it to send.
 * A `pump()` then hand-delivers one connection's buffered output into the other's `read_stream`, in
 * both directions, until the conversation settles. nghttp3 does the real QPACK encode/decode over its
 * control + encoder/decoder streams, so the field blocks the client submits are genuinely parsed back
 * into a typed `qb::http::Request` on the server (and the response into a `qb::http::Response` on the
 * client) — proving the adapter end-to-end with zero network, zero TLS, fully deterministic and
 * parallel-safe. It is system-tier (it needs the live nghttp3 engine) but needs no daemon and no cert.
 *
 * Gated on `QBM_HTTP_HAS_HTTP3` (the adapter only exists in an HTTP/3 build).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <qbm/http/http.h>

#if defined(QBM_HTTP_HAS_HTTP3)

#include <algorithm>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <qb/system/container/unordered_map.h>
#include <nghttp3/nghttp3.h>

// The heap in use, as glibc's mallinfo2() reports it: the measure of what a stream's state keeps. Not where a
// sanitizer's allocator stands in for glibc's, nor off glibc.
#if defined(__GLIBC__)
#include <malloc.h>
#define QBM_HTTP_TEST_HEAP_IN_USE 1
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#undef QBM_HTTP_TEST_HEAP_IN_USE
#define QBM_HTTP_TEST_HEAP_IN_USE 0
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || __has_feature(memory_sanitizer)
#undef QBM_HTTP_TEST_HEAP_IN_USE
#define QBM_HTTP_TEST_HEAP_IN_USE 0
#endif
#endif
#else
#define QBM_HTTP_TEST_HEAP_IN_USE 0
#endif

namespace {

using qb::protocol::http3::connection;
// NOTE: `connection<Owner>::role` is a member enum, so each instantiation has its own `role` type.
// Use ClientConnection::role / ServerConnection::role at each construction site (no shared alias).

// ---------------------------------------------------------------------------
// A buffered HTTP/3 transport double. nghttp3 (via the connection adapter) calls
// send_http3_stream_data / open_http3_unidirectional_stream / extend / reset / ...
// We just RECORD the bytes per stream so a pump can feed them into the peer's
// connection<>::read_stream(). QUIC-correct stream-id parity is handed out so
// nghttp3 accepts the control / qpack uni-streams:
//   - client uni streams: 2, 6, 10, ...  (bit0=0 client, bit1=1 uni)
//   - server uni streams: 3, 7, 11, ...  (bit0=1 server, bit1=1 uni)
// Request (bidi, client-initiated) streams are allocated by the test: 0, 4, 8, ...
// ---------------------------------------------------------------------------
struct frame {
    std::uint64_t stream_id;
    std::string   data;
    bool          fin;
};

struct DirectOwnerBase {
    bool                                                 server_role = false;
    std::uint64_t                                        next_uni    = 0; // seeded in ctor per role
    std::deque<frame>                                    outbound;        // bytes nghttp3 wants on the wire
    qb::unordered_map<std::uint64_t, std::uint64_t>      credit;          // stream_id -> total credit extended
    std::vector<std::pair<std::uint64_t, std::uint64_t>> resets;          // (stream_id, code)
    std::vector<std::pair<std::uint64_t, std::uint64_t>> stops;           // (stream_id, code)
    std::vector<std::pair<std::uint64_t, std::uint64_t>> acks;            // (stream_id, bytes)
    std::optional<std::pair<std::uint64_t, std::string>> close;           // (code, reason) once
    std::vector<std::uint64_t>                           drained;         // streams whose output drained
    std::vector<std::uint64_t>                           shutdowns;       // last-ids from GOAWAY

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
    on_http3_stream_acked(std::uint64_t stream_id, std::uint64_t bytes) {
        acks.emplace_back(stream_id, bytes);
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

// Server-role owner: receives requests; uses the 3-arg stream-closed hook the server adapter detects.
struct ServerOwner : DirectOwnerBase {
    std::vector<qb::http::Request> requests;

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
    // body cap: 0 means unlimited (no max_http3_body_size override here -> the `requires` arm is skipped)
};

// Client-role owner: receives responses; uses the 2-arg stream-closed hook the client adapter detects.
struct ClientOwner : DirectOwnerBase {
    std::vector<qb::http::Response> responses;

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
};

using ServerConnection = connection<ServerOwner>;
using ClientConnection = connection<ClientOwner>;

// Deliver every buffered frame from one side's owner into the peer connection. Returns the number of
// frames moved so the caller can pump until the conversation is quiescent.
template <typename FromOwner, typename ToConn>
std::size_t
deliver(FromOwner &from_owner, ToConn &to_conn, qb::unordered_map<std::uint64_t, std::uint64_t> *wire_bytes = nullptr) {
    std::size_t moved = 0;
    auto        queue = std::move(from_owner.outbound);
    from_owner.outbound.clear();
    for (auto &f : queue) {
        ++moved;
        if (wire_bytes) {
            (*wire_bytes)[f.stream_id] += f.data.size();
        }
        to_conn.read_stream(f.stream_id, f.data, f.fin);
    }
    return moved;
}

// Pump bytes back and forth until neither side has anything left to deliver (bounded so a logic bug
// can never spin forever). Templated so a derived owner/connection (e.g. a body-capped server) pumps too.
template <typename ClientOwnerT, typename ClientConnT, typename ServerOwnerT, typename ServerConnT>
void
pump(ClientOwnerT &client_owner, ClientConnT &client_conn, ServerOwnerT &server_owner, ServerConnT &server_conn,
     qb::unordered_map<std::uint64_t, std::uint64_t> *client_wire_bytes = nullptr,
     qb::unordered_map<std::uint64_t, std::uint64_t> *server_wire_bytes = nullptr) {
    for (int i = 0; i < 64; ++i) {
        const auto a = deliver(client_owner, server_conn, client_wire_bytes);
        const auto b = deliver(server_owner, client_conn, server_wire_bytes);
        if (a == 0 && b == 0)
            return;
    }
}

// ---------------------------------------------------------------------------
// Raw HTTP/3 frames, built WITHOUT the adapter's outgoing validation: what a malformed peer sends
// (Huly QB-234). The field block is QPACK-encoded by nghttp3's own encoder over the static table
// alone (a zero-capacity dynamic table), so it needs no encoder stream and decodes before any
// SETTINGS. A frame is its type, its length and its payload, each length a QUIC varint.
// ---------------------------------------------------------------------------
std::string
h3_varint(std::uint64_t v) {
    std::string out;
    if (v < 64) {
        out.push_back(static_cast<char>(v));
    } else if (v < 16384) {
        out.push_back(static_cast<char>(0x40 | (v >> 8)));
        out.push_back(static_cast<char>(v & 0xff));
    } else {
        out.push_back(static_cast<char>(0x80 | (v >> 24)));
        out.push_back(static_cast<char>((v >> 16) & 0xff));
        out.push_back(static_cast<char>((v >> 8) & 0xff));
        out.push_back(static_cast<char>(v & 0xff));
    }
    return out;
}

std::string
h3_frame(std::uint64_t type, std::string const &payload) {
    return h3_varint(type) + h3_varint(payload.size()) + payload;
}

// A HEADERS frame (type 0x1) carrying `fields` in the given order, encoded for `stream_id`.
std::string
h3_headers_frame(std::uint64_t stream_id, std::vector<std::pair<std::string, std::string>> const &fields) {
    std::vector<nghttp3_nv> nva;
    nva.reserve(fields.size());
    for (auto const &[name, value] : fields) {
        nva.push_back(nghttp3_nv{
            reinterpret_cast<uint8_t *>(const_cast<char *>(name.data())), reinterpret_cast<uint8_t *>(const_cast<char *>(value.data())),
            name.size(), value.size(), NGHTTP3_NV_FLAG_NONE
        });
    }
    nghttp3_qpack_encoder *encoder = nullptr;
    EXPECT_EQ(nghttp3_qpack_encoder_new(&encoder, 0, nghttp3_mem_default()), 0);
    nghttp3_buf pbuf, rbuf, ebuf;
    nghttp3_buf_init(&pbuf);
    nghttp3_buf_init(&rbuf);
    nghttp3_buf_init(&ebuf);
    EXPECT_EQ(nghttp3_qpack_encoder_encode(encoder, &pbuf, &rbuf, &ebuf, static_cast<int64_t>(stream_id), nva.data(), nva.size()), 0);
    EXPECT_EQ(nghttp3_buf_len(&ebuf), 0u) << "a static-table-only block writes nothing to the encoder stream";
    std::string block(reinterpret_cast<char const *>(pbuf.pos), nghttp3_buf_len(&pbuf));
    block.append(reinterpret_cast<char const *>(rbuf.pos), nghttp3_buf_len(&rbuf));
    nghttp3_buf_free(&pbuf, nghttp3_mem_default());
    nghttp3_buf_free(&rbuf, nghttp3_mem_default());
    nghttp3_buf_free(&ebuf, nghttp3_mem_default());
    nghttp3_qpack_encoder_del(encoder);
    return h3_frame(0x1, block);
}

std::string
h3_data_frame(std::string const &body) {
    return h3_frame(0x0, body);
}

// A well-formed request field block: the four pseudo-headers, in order.
std::vector<std::pair<std::string, std::string>>
request_fields(std::string path = "/") {
    return {{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", std::move(path)}};
}

// A connected client+server pair with their control/qpack streams bound.
struct Pair {
    ClientOwner      client_owner;
    ServerOwner      server_owner;
    ClientConnection client{client_owner, 1, ClientConnection::role::client};
    ServerConnection server{server_owner, 1, ServerConnection::role::server};

    Pair() {
        EXPECT_TRUE(client.ok());
        EXPECT_TRUE(server.ok());
        EXPECT_TRUE(client.bind_local_streams());
        EXPECT_TRUE(server.bind_local_streams());
        settle();
    }

    void
    settle() {
        pump(client_owner, client, server_owner, server);
    }
};

} // namespace

// =============================================================================
// CONSTRUCTION + LOCAL STREAM BINDING
// =============================================================================

/**
 * @test A fresh connection is live and binding the control/qpack streams is idempotent
 * @brief The ctor creates a real nghttp3_conn (ok()==true); bind_local_streams() opens exactly three
 *        unidirectional streams (control + qpack encoder + decoder) on first call, drains the initial
 *        SETTINGS/QPACK output to the owner, and is a no-op on a second call.
 */
TEST(Http3ConnectionDirect, BindsLocalStreamsOnceAndDrainsInitialOutput) {
    ClientOwner      owner;
    ClientConnection conn{owner, 1, ClientConnection::role::client};
    ASSERT_TRUE(conn.ok());

    EXPECT_TRUE(conn.bind_local_streams());
    // control(2) + qpack-encoder(6) + qpack-decoder(10) were opened.
    EXPECT_EQ(owner.next_uni, 2u + 12u);
    // The control stream's SETTINGS frame was drained out to the transport.
    EXPECT_FALSE(owner.outbound.empty()) << "initial control-stream output must be drained on bind";

    const auto opened_after_first = owner.next_uni;
    EXPECT_TRUE(conn.bind_local_streams()) << "a second bind is an idempotent no-op";
    EXPECT_EQ(owner.next_uni, opened_after_first) << "no extra streams opened on the second bind";
}

// =============================================================================
// REQUEST -> SERVER : full QPACK decode into a typed Request
// =============================================================================

/**
 * @test A submitted client request is decoded into a typed Request on the server
 * @brief submit_request encodes :method/:scheme/:authority/:path + a regular header through nghttp3's
 *        real QPACK encoder; pumping the bytes to the server drives recv_header_cb -> materialize_headers
 *        -> end_stream_cb -> on_http3_request, yielding a qb::http::Request whose method, path, version
 *        and custom header survived the round-trip.
 */
TEST(Http3ConnectionDirect, ClientRequestIsDecodedIntoTypedRequestOnServer) {
    Pair pair;

    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/api/items?page=2")};
    request.set_header("x-trace", "abc-123");

    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();

    ASSERT_EQ(pair.server_owner.requests.size(), 1u);
    auto const &got = pair.server_owner.requests.front();
    EXPECT_EQ(got.method(), qb::http::method::GET);
    EXPECT_EQ(got.uri().path(), "/api/items");
    EXPECT_EQ(static_cast<int>(got.major_version), 3);
    EXPECT_EQ(got.stream_id, 0u);
    EXPECT_EQ(got.header("x-trace"), "abc-123");
}

/**
 * @test A POST body is delivered to the server via recv_data_cb and content-length reconciles
 * @brief A request with a body and a matching content-length drives recv_data_cb (body bytes) and
 *        end_stream_cb's content_length_matches check; the server materializes a Request whose body
 *        equals the sent payload. Proves the data-callback + length-reconciliation arm end-to-end.
 */
TEST(Http3ConnectionDirect, ClientRequestBodyReachesServerAndContentLengthMatches) {
    Pair pair;

    qb::http::Request request{qb::http::method::POST, qb::io::uri("https://example.test/upload")};
    request.body() = "payload-bytes";
    request.set_header("content-length", std::to_string(std::string("payload-bytes").size()));

    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();

    ASSERT_EQ(pair.server_owner.requests.size(), 1u);
    auto const &got = pair.server_owner.requests.front();
    EXPECT_EQ(got.method(), qb::http::method::POST);
    EXPECT_EQ(got.body().template as<std::string>(), "payload-bytes");
    // The connection had no protocol error (no close was forced).
    EXPECT_FALSE(pair.server_owner.close.has_value()) << "a matching content-length must not close the connection";
}

/**
 * @test Every accepted HTTP/3 DATA byte restores QUIC stream and connection credit
 * @brief nghttp3_conn_read_stream2 returns framing bytes but excludes DATA payloads. The direct
 *        owner records every received wire byte and every requested credit extension, so this
 *        test checks exact accounting in both request and response directions without a socket.
 */
TEST(Http3ConnectionDirect, AcceptedBodyRestoresAllStreamCreditInBothDirections) {
    Pair                                            pair;
    qb::unordered_map<std::uint64_t, std::uint64_t> request_wire;
    qb::unordered_map<std::uint64_t, std::uint64_t> response_wire;

    qb::http::Request request{qb::http::method::POST, qb::io::uri("https://example.test/upload")};
    request.body() = std::string(8192, 'Q');
    request.set_header("content-length", "8192");
    ASSERT_TRUE(pair.client.submit_request(0, request));
    pump(pair.client_owner, pair.client, pair.server_owner, pair.server, &request_wire, &response_wire);

    ASSERT_EQ(pair.server_owner.requests.size(), 1u);
    EXPECT_EQ(pair.server_owner.requests.front().body().size(), 8192u);
    ASSERT_GT(request_wire[0], 8192u);
    EXPECT_EQ(pair.server_owner.credit[0], request_wire[0]);

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = std::string(12288, 'R');
    ASSERT_TRUE(pair.server.submit_response(0, response));
    pump(pair.client_owner, pair.client, pair.server_owner, pair.server, &request_wire, &response_wire);

    ASSERT_EQ(pair.client_owner.responses.size(), 1u);
    EXPECT_EQ(pair.client_owner.responses.front().body().size(), 12288u);
    ASSERT_GT(response_wire[0], 12288u);
    EXPECT_EQ(pair.client_owner.credit[0], response_wire[0]);
}

// =============================================================================
// RESPONSE -> CLIENT : full QPACK decode into a typed Response
// =============================================================================

/**
 * @test A server response is decoded into a typed Response on the client
 * @brief After the request arrives, submit_response encodes :status + headers + body; pumping back to
 *        the client drives the client-role materialize_headers (:status arm) -> on_http3_response. The
 *        client observes a Response with the right status, header, body, and HTTP/3 version. Also
 *        exercises read_data_cb (the body reader) and the FIN/output-drained bookkeeping in drain().
 */
TEST(Http3ConnectionDirect, ServerResponseIsDecodedIntoTypedResponseOnClient) {
    Pair pair;

    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/resource")};
    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();
    ASSERT_EQ(pair.server_owner.requests.size(), 1u);

    qb::http::Response response;
    response.status() = qb::http::status::CREATED;
    response.set_header("x-served-by", "direct-harness");
    response.body() = "hello-h3";

    ASSERT_TRUE(pair.server.submit_response(0, response));
    pair.settle();

    ASSERT_EQ(pair.client_owner.responses.size(), 1u);
    auto const &got = pair.client_owner.responses.front();
    EXPECT_EQ(got.status().code(), 201);
    EXPECT_EQ(static_cast<int>(got.major_version), 3);
    EXPECT_EQ(got.header("x-served-by"), "direct-harness");
    EXPECT_EQ(got.body().template as<std::string>(), "hello-h3");
    EXPECT_EQ(got.stream_id, 0u);

    // The server's response output stream reached FIN, so on_http3_stream_output_drained fired once.
    EXPECT_FALSE(pair.server_owner.drained.empty()) << "the drained-output hook should fire on FIN";
}

// =============================================================================
// TRAILERS — announced request trailers decode into extra headers on the server
// =============================================================================

/**
 * @test Announced request trailers are submitted, decoded, and appended on the server
 * @brief submit_request with a `trailer` header builds a trailer field block (make_trailers) and calls
 *        nghttp3_conn_submit_trailers; on the server begin/end_trailers_cb -> materialize_trailers
 *        appends the trailer field to the materialized Request after the main headers were seen.
 */
TEST(Http3ConnectionDirect, AnnouncedRequestTrailersAreDeliveredToServer) {
    Pair pair;

    qb::http::Request request{qb::http::method::POST, qb::io::uri("https://example.test/stream")};
    request.body() = "chunk";
    request.set_header("content-length", "5");
    request.set_header("trailer", "x-checksum");
    request.set_header("x-checksum", "deadbeef");

    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();

    ASSERT_EQ(pair.server_owner.requests.size(), 1u);
    auto const &got = pair.server_owner.requests.front();
    EXPECT_EQ(got.body().template as<std::string>(), "chunk");
    EXPECT_EQ(got.header("x-checksum"), "deadbeef") << "3.x: the trailer field is one of the header fields too";
    EXPECT_EQ(got.trailers().header("x-checksum"), "deadbeef") << "the trailer field is the request's trailers() (Huly QB-1073)";
    EXPECT_EQ(got.trailers().header_count(), 1u);
    EXPECT_FALSE(pair.server_owner.close.has_value());
}

/**
 * @test trailers() crosses an HTTP/3 exchange both ways
 * @brief What a request or a response carries in its trailers() is what the peer finds in its own --
 *        the header fields keep it too, for 3.x -- with a body or without one, announced by a
 *        `trailer` field the sender adds (Huly QB-1073).
 */
TEST(Http3ConnectionDirect, TrailersContainerCrossesBothDirections) {
    for (const bool with_body : {true, false}) {
        Pair pair;

        qb::http::Request request{qb::http::method::POST, qb::io::uri("https://example.test/both-ways")};
        if (with_body) {
            request.body() = "request-body";
        }
        request.trailers().set_header("x-request-sum", "r1");
        ASSERT_TRUE(pair.client.submit_request(0, request)) << "body " << with_body;
        pair.settle();
        ASSERT_EQ(pair.server_owner.requests.size(), 1u) << "body " << with_body;
        auto const &got = pair.server_owner.requests.front();
        EXPECT_EQ(got.body().template as<std::string>(), with_body ? "request-body" : "");
        EXPECT_EQ(got.trailers().header_count(), 1u);
        EXPECT_EQ(got.trailers().header("x-request-sum"), "r1");
        EXPECT_EQ(got.header("trailer"), "x-request-sum") << "the announcement is a header field";
        EXPECT_EQ(got.header("x-request-sum"), "r1");

        qb::http::Response response;
        response.status() = qb::http::status::OK;
        if (with_body) {
            response.body() = "response-body";
        }
        response.trailers().set_header("grpc-status", "0");
        ASSERT_TRUE(pair.server.submit_response(0, response)) << "body " << with_body;
        pair.settle();
        ASSERT_EQ(pair.client_owner.responses.size(), 1u) << "body " << with_body;
        auto const &received = pair.client_owner.responses.front();
        EXPECT_EQ(received.body().template as<std::string>(), with_body ? "response-body" : "");
        EXPECT_EQ(received.trailers().header_count(), 1u);
        EXPECT_EQ(received.trailers().header("grpc-status"), "0");
        EXPECT_FALSE(pair.client_owner.close.has_value());
        EXPECT_FALSE(pair.server_owner.close.has_value());
    }
}

/**
 * @test A response that announces a trailer field it does not set ends after its body
 * @brief The `trailer` header is a hint: HTTP/1.1 and HTTP/2 end such a message with an empty trailer
 *        section. HTTP/3 refused it -- submit_response returned false after the headers and body
 *        were already queued (Huly QB-1073).
 */
TEST(Http3ConnectionDirect, AnAnnouncedButUnsetTrailerFieldEndsTheResponseAfterItsBody) {
    Pair              pair;
    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/announced")};
    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();
    ASSERT_EQ(pair.server_owner.requests.size(), 1u);

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = "body";
    response.set_header("trailer", "x-checksum"); // announced, never set
    ASSERT_TRUE(pair.server.submit_response(0, response));
    pair.settle();
    ASSERT_EQ(pair.client_owner.responses.size(), 1u);
    EXPECT_EQ(pair.client_owner.responses.front().body().template as<std::string>(), "body");
    EXPECT_FALSE(pair.client_owner.responses.front().has_header("x-checksum"));
}

/**
 * @test A trailer section follows an empty body
 * @brief Without a data reader nghttp3 ends the stream on the HEADERS, and the trailer submission that
 *        follows fails: an empty-bodied response with trailers was refused, after its headers were
 *        queued (Huly QB-1073). The reader is given whenever trailers follow.
 */
TEST(Http3ConnectionDirect, ATrailerSectionFollowsAnEmptyBody) {
    Pair              pair;
    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/empty")};
    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();
    ASSERT_EQ(pair.server_owner.requests.size(), 1u);

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("trailer", "x-checksum");
    response.set_header("x-checksum", "abc");
    ASSERT_TRUE(pair.server.submit_response(0, response));
    pair.settle();
    ASSERT_EQ(pair.client_owner.responses.size(), 1u);
    EXPECT_TRUE(pair.client_owner.responses.front().body().empty());
    EXPECT_EQ(pair.client_owner.responses.front().header("x-checksum"), "abc");
}

/**
 * @test A forbidden field of trailers() refuses the submission before anything is queued
 * @brief The trailer section is built and checked before the headers are submitted: a field it must
 *        not carry (the shared list) refuses the message, and the stream stays unused (Huly QB-1073).
 */
TEST(Http3ConnectionDirect, AForbiddenTrailerFieldRefusesTheSubmissionBeforeAnythingIsQueued) {
    Pair              pair;
    qb::http::Request request{qb::http::method::POST, qb::io::uri("https://example.test/forbidden")};
    request.body() = "abc";
    request.trailers().set_header("content-length", "3");
    EXPECT_FALSE(pair.client.submit_request(0, request));
    pair.settle();
    EXPECT_TRUE(pair.server_owner.requests.empty());

    // The stream was left unused: the same stream id still takes a request.
    qb::http::Request next{qb::http::method::GET, qb::io::uri("https://example.test/next")};
    ASSERT_TRUE(pair.client.submit_request(0, next));
    pair.settle();
    ASSERT_EQ(pair.server_owner.requests.size(), 1u);
    EXPECT_EQ(pair.server_owner.requests.front().uri().path(), "/next");
}

// =============================================================================
// SUBMIT-TIME REJECTIONS (validation arms in submit_request / submit_response)
// =============================================================================

/**
 * @test A request's content-length is its body's (Huly QB-1191)
 * @brief The declared content-length is left out and the body's written, as the HTTP/2 client does: a request whose
 *        body contradicted its declared length was refused before anything was sent, and HTTP/2 sent it. The server
 *        receives the body and the length that frames it.
 */
TEST(Http3ConnectionDirect, ARequestSendsTheContentLengthOfItsBody) {
    Pair pair;

    qb::http::Request request{qb::http::method::POST, qb::io::uri("https://example.test/x")};
    request.body() = "12345";
    request.set_header("content-length", "99");

    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();
    ASSERT_EQ(pair.server_owner.requests.size(), 1u);
    EXPECT_EQ(pair.server_owner.requests.front().header("content-length"), "5");
    EXPECT_EQ(pair.server_owner.requests.front().body().template as<std::string>(), "12345");
    EXPECT_TRUE(pair.server_owner.resets.empty());
    EXPECT_FALSE(pair.server_owner.close.has_value());
}

/**
 * @test A request leaves without the fields the server refuses (Huly QB-1191)
 * @brief A connection-specific field (RFC 9114 section 4.2) and the fields its `connection` header names are left out,
 *        as the HTTP/2 client leaves them out and as an intermediary translating an HTTP/1.1 message removes them: a
 *        request carrying `Connection: keep-alive` was refused whole before anything was sent, and HTTP/2 served it.
 *        The request is served with the other fields.
 */
TEST(Http3ConnectionDirect, ARequestLeavesWithoutTheFieldsTheServerRefuses) {
    Pair pair;

    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/x")};
    request.set_header("Connection", "keep-alive, X-Hop");
    request.set_header("Keep-Alive", "timeout=5");
    request.set_header("Transfer-Encoding", "chunked");
    request.set_header("X-Hop", "1");
    request.set_header("X-Kept", "2");

    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();
    ASSERT_EQ(pair.server_owner.requests.size(), 1u);
    auto const &served = pair.server_owner.requests.front();
    EXPECT_EQ(served.uri().path(), "/x");
    for (const char *name : {"connection", "keep-alive", "transfer-encoding", "x-hop"}) {
        EXPECT_FALSE(served.has_header(name)) << name;
    }
    EXPECT_EQ(served.header("x-kept"), "2");
    EXPECT_TRUE(pair.server_owner.resets.empty());
    EXPECT_FALSE(pair.server_owner.close.has_value());
}

/**
 * @test A `te` field other than `trailers` never leaves (Huly QB-1191)
 * @brief RFC 9114 section 4.2: a request carries `te` as `trailers` alone. `te: gzip` was submitted, and the peer's
 *        nghttp3 took it for a malformed message -- a connection error, every stream with it; then it refused the
 *        request whole. It is left out, as the HTTP/2 client leaves it out, and the request is served; `te: trailers`
 *        crosses, and the connection serves the next request.
 */
TEST(Http3ConnectionDirect, ATeFieldOtherThanTrailersIsNeverSubmitted) {
    Pair pair;

    qb::http::Request gzip{qb::http::method::GET, qb::io::uri("https://example.test/gzip")};
    gzip.set_header("TE", "gzip");
    ASSERT_TRUE(pair.client.submit_request(0, gzip));
    pair.settle();
    ASSERT_EQ(pair.server_owner.requests.size(), 1u);
    EXPECT_EQ(pair.server_owner.requests.front().uri().path(), "/gzip");
    EXPECT_FALSE(pair.server_owner.requests.front().has_header("te"));
    EXPECT_FALSE(pair.server_owner.close.has_value()) << "the peer closed the connection with " << pair.server_owner.close->first;

    qb::http::Request trailers{qb::http::method::GET, qb::io::uri("https://example.test/trailers")};
    trailers.set_header("TE", "trailers");
    ASSERT_TRUE(pair.client.submit_request(4, trailers));
    pair.settle();
    ASSERT_EQ(pair.server_owner.requests.size(), 2u);
    EXPECT_EQ(pair.server_owner.requests.back().uri().path(), "/trailers");
    EXPECT_EQ(pair.server_owner.requests.back().header("te"), "trailers");
    EXPECT_FALSE(pair.server_owner.close.has_value());
}

/**
 * @test The proxy authentication fields cross a header section both ways (Huly QB-1197)
 * @brief RFC 9114 section 4.2 does not count `proxy-authorization` and `proxy-authenticate` among the
 *        connection-specific fields, and HTTP/2 serves them: a request carrying one was refused with H3_MESSAGE_ERROR
 *        on receipt and before submission, a response carrying the other was never submitted. A request sent by the
 *        client and one built on the wire are served with the field; the 407 that answers them is delivered with its
 *        challenge; the connection serves on.
 */
TEST(Http3ConnectionDirect, TheProxyAuthenticationFieldsCrossAHeaderSection) {
    Pair pair;

    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/proxied")};
    request.set_header("Proxy-Authorization", "Basic dXNlcjpwYXNz");
    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();
    ASSERT_EQ(pair.server_owner.requests.size(), 1u);
    EXPECT_EQ(pair.server_owner.requests.front().header("proxy-authorization"), "Basic dXNlcjpwYXNz");

    qb::http::Response response;
    response.status() = qb::http::status::PROXY_AUTHENTICATION_REQUIRED;
    response.set_header("Proxy-Authenticate", "Basic realm=\"proxy\"");
    ASSERT_TRUE(pair.server.submit_response(0, response));
    pair.settle();
    ASSERT_EQ(pair.client_owner.responses.size(), 1u);
    EXPECT_EQ(pair.client_owner.responses.front().status(), qb::http::status::PROXY_AUTHENTICATION_REQUIRED);
    EXPECT_EQ(pair.client_owner.responses.front().header("proxy-authenticate"), "Basic realm=\"proxy\"");

    auto fields = request_fields("/raw");
    fields.emplace_back("proxy-authorization", "Basic x");
    pair.server.read_stream(4, h3_headers_frame(4, fields), true);
    ASSERT_EQ(pair.server_owner.requests.size(), 2u) << "a request built on the wire is served";
    EXPECT_EQ(pair.server_owner.requests.back().header("proxy-authorization"), "Basic x");
    EXPECT_TRUE(pair.server_owner.resets.empty());
    EXPECT_FALSE(pair.server_owner.close.has_value());
}

/**
 * @test A field value with SP or HTAB at an end never reaches the server (Huly QB-1191)
 * @brief Such a value is malformed (RFC 9114 section 4.2, RFC 9110 section 5.5's field-content). nghttp3 (1.18.0) removes
 *        the field before this module sees it -- the request is served without it, which this pins, so that a nghttp3
 *        that delivers it shows here: this module would then refuse the stream (is_valid_incoming_header_field). A
 *        response carrying one is never submitted, and the connection serves on.
 */
TEST(Http3ConnectionDirect, AFieldValueWithWhitespaceAtAnEndNeverReachesTheServer) {
    Pair pair;

    auto fields = request_fields("/edge");
    fields.emplace_back("x-edge", "a ");
    fields.emplace_back("x-tab", "\ta");
    fields.emplace_back("x-kept", "a \t b");
    pair.server.read_stream(0, h3_headers_frame(0, fields), true);
    ASSERT_EQ(pair.server_owner.requests.size(), 1u) << "nghttp3 removes the field, and the request is served";
    auto const &served = pair.server_owner.requests.front();
    EXPECT_FALSE(served.has_header("x-edge"));
    EXPECT_FALSE(served.has_header("x-tab"));
    EXPECT_EQ(served.header("x-kept"), "a \t b") << "whitespace inside a value is part of it";

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("x-edge", " a");
    EXPECT_FALSE(pair.server.submit_response(0, response));
    response.set_header("x-edge", "a");
    EXPECT_TRUE(pair.server.submit_response(0, response));
    pair.settle();
    EXPECT_TRUE(pair.server_owner.resets.empty());
    EXPECT_FALSE(pair.server_owner.close.has_value());
}

/**
 * @test A response's `host` crosses (Huly QB-1189)
 * @brief The server sends a response's `host` field, as HTTP/1.1 and HTTP/2 send it, and the client delivers it: it is no
 *        connection-specific field (RFC 9114 section 4.2) and names no authority. The HTTP/3 server dropped it.
 */
TEST(Http3ConnectionDirect, AResponseHostFieldReachesTheClient) {
    Pair pair;

    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/x")};
    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();
    ASSERT_EQ(pair.server_owner.requests.size(), 1u);

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("Host", "example.test");
    ASSERT_TRUE(pair.server.submit_response(0, response));
    pair.settle();
    ASSERT_EQ(pair.client_owner.responses.size(), 1u);
    EXPECT_EQ(pair.client_owner.responses.front().header("host"), "example.test");
    EXPECT_FALSE(pair.client_owner.close.has_value());
}

/**
 * @test submit_response rejects a forbidden response header
 * @brief transfer-encoding is forbidden in HTTP/3; make_response_headers returns nullopt so
 *        submit_response returns false (server side) and the client never receives a response.
 */
TEST(Http3ConnectionDirect, SubmitResponseRejectsForbiddenHeader) {
    Pair pair;

    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/x")};
    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();
    ASSERT_EQ(pair.server_owner.requests.size(), 1u);

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("transfer-encoding", "chunked");

    EXPECT_FALSE(pair.server.submit_response(0, response));
    pair.settle();
    EXPECT_TRUE(pair.client_owner.responses.empty());
}

/**
 * @test An announced field a trailer section must not carry stays in the header section
 * @brief A response that announces `trailer: content-length` sends its `content-length` in its header
 *        section, as HTTP/1.1 and HTTP/2 do: one rule for the three protocols (Huly QB-1073). HTTP/3
 *        refused it -- submit_response returned false, after the headers were queued.
 */
TEST(Http3ConnectionDirect, AnAnnouncedForbiddenTrailerFieldStaysInTheHeaderSection) {
    Pair pair;

    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/x")};
    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("trailer", "content-length"); // content-length is a forbidden trailer name
    response.set_header("content-length", "3");
    response.body() = "abc";

    ASSERT_TRUE(pair.server.submit_response(0, response));
    pair.settle();
    ASSERT_EQ(pair.client_owner.responses.size(), 1u);
    EXPECT_EQ(pair.client_owner.responses.front().header("content-length"), "3");
    EXPECT_EQ(pair.client_owner.responses.front().body().template as<std::string>(), "abc");
}

// =============================================================================
// INBOUND BODY CAP -- a request over the owner's cap is ANSWERED 413 on its stream (Huly QB-168)
// =============================================================================

namespace {

// A server owner that advertises a tight body cap, so the `requires` arms are compiled in.
struct CappedServerOwner : ServerOwner {
    std::uint64_t
    max_http3_body_size() const noexcept {
        return 16; // bytes
    }
};
using CappedServerConnection = connection<CappedServerOwner>;

[[nodiscard]] bool
stopped_without_error(DirectOwnerBase const &owner, std::uint64_t stream_id) {
    return std::any_of(owner.stops.begin(), owner.stops.end(),
                       [&](auto const &s) { return s.first == stream_id && s.second == static_cast<std::uint64_t>(NGHTTP3_H3_NO_ERROR); });
}

[[nodiscard]] bool
reset(DirectOwnerBase const &owner, std::uint64_t stream_id) {
    return std::any_of(owner.resets.begin(), owner.resets.end(), [&](auto const &r) { return r.first == stream_id; });
}

} // namespace

/**
 * @test A request DECLARING a body over the owner's cap is answered 413, then STOP_SENDING(H3_NO_ERROR)
 * @brief When the Owner exposes max_http3_body_size() (detected via `requires`), end_headers_cb compares the
 *        declared content-length with it once the header section is materialized: over it, the request is
 *        never handed to the owner; a complete 413 response is submitted on the stream, then the read side
 *        is stopped with H3_NO_ERROR (RFC 9114 section 4.1.1) -- the answer HTTP/1.1 and HTTP/2 give. It was a
 *        reset (H3_REQUEST_CANCELLED), a client's 502, until 3.3. The client decodes the 413; a request at
 *        the cap, on the same connection, is served.
 */
TEST(Http3ConnectionDirect, ServerAnswersARequestDeclaringABodyOverTheCapWith413) {
    ClientOwner            client_owner;
    CappedServerOwner      server_owner;
    ClientConnection       client{client_owner, 1, ClientConnection::role::client};
    CappedServerConnection server{server_owner, 1, CappedServerConnection::role::server};
    ASSERT_TRUE(client.bind_local_streams());
    ASSERT_TRUE(server.bind_local_streams());
    pump(client_owner, client, server_owner, server);

    qb::http::Request request{qb::http::method::POST, qb::io::uri("https://example.test/upload")};
    request.body() = std::string(64, 'B'); // well over the 16-byte cap
    request.set_header("content-length", "64");

    ASSERT_TRUE(client.submit_request(0, request));
    qb::unordered_map<std::uint64_t, std::uint64_t> request_wire;
    pump(client_owner, client, server_owner, server, &request_wire);

    EXPECT_TRUE(server_owner.requests.empty()) << "an over-cap request must not be delivered";
    EXPECT_EQ(server_owner.credit[0], request_wire[0]) << "discarded DATA still consumes QUIC connection credit";
    EXPECT_TRUE(stopped_without_error(server_owner, 0)) << "the client is asked to stop sending, without an error";
    EXPECT_FALSE(reset(server_owner, 0)) << "the request is answered, not reset";
    ASSERT_EQ(client_owner.responses.size(), 1u) << "the client receives the answer";
    EXPECT_EQ(client_owner.responses.front().status(), qb::http::status::PAYLOAD_TOO_LARGE);
    EXPECT_FALSE(server_owner.close.has_value()) << "the connection survives";

    qb::http::Request at_cap{qb::http::method::POST, qb::io::uri("https://example.test/upload")};
    at_cap.body() = std::string(16, 'C');
    ASSERT_TRUE(client.submit_request(4, at_cap));
    pump(client_owner, client, server_owner, server);
    ASSERT_EQ(server_owner.requests.size(), 1u) << "a body exactly at the cap is served";
    EXPECT_EQ(server_owner.requests.front().body().size(), 16u);
}

/**
 * @test A body that passes the cap WITHOUT a declared content-length is answered 413 when it does
 * @brief recv_data_cb tracks the accumulating body: 16 bytes of 16 pass, the 17th refuses the request --
 *        never delivered, its read side stopped with H3_NO_ERROR after a complete response (FIN), no reset
 *        -- and the bytes the peer still sends are dropped, their credit returned.
 */
TEST(Http3ConnectionDirect, ServerAnswersABodyPassingTheCapWith413) {
    ClientOwner            client_owner;
    CappedServerOwner      server_owner;
    ClientConnection       client{client_owner, 1, ClientConnection::role::client};
    CappedServerConnection server{server_owner, 1, CappedServerConnection::role::server};
    ASSERT_TRUE(client.bind_local_streams());
    ASSERT_TRUE(server.bind_local_streams());
    pump(client_owner, client, server_owner, server);

    auto fields      = request_fields("/upload");
    fields[0].second = "POST";
    server.read_stream(0, h3_headers_frame(0, fields), false);
    server.read_stream(0, h3_data_frame(std::string(16, 'B')), false);
    EXPECT_TRUE(server_owner.stops.empty()) << "16 bytes of 16: not yet";
    server.read_stream(0, h3_data_frame("x"), false);

    EXPECT_TRUE(server_owner.requests.empty());
    EXPECT_TRUE(stopped_without_error(server_owner, 0));
    EXPECT_FALSE(reset(server_owner, 0));
    EXPECT_TRUE(std::any_of(server_owner.outbound.begin(), server_owner.outbound.end(), [](frame const &f) {
        return f.stream_id == 0 && f.fin;
    })) << "a complete response ends the stream";
    const auto credit_before = server_owner.credit[0];
    server.read_stream(0, h3_data_frame(std::string(32, 'C')), true); // in flight before the stop
    EXPECT_TRUE(server_owner.requests.empty());
    EXPECT_GT(server_owner.credit[0], credit_before) << "dropped bytes return their credit";
    EXPECT_FALSE(server_owner.close.has_value());
}

// =============================================================================
// MALFORMED MESSAGES: THE STREAM IS REFUSED FOR WHAT THIS ADAPTER CHECKS, THE CONNECTION CLOSED
// FOR WHAT nghttp3 CHECKS FIRST (Huly QB-234)
// =============================================================================
//
// RFC 9114 section 4.1.2 makes a malformed request or response a STREAM error, H3_MESSAGE_ERROR.
// Two validators see every message. nghttp3's own runs first, inside nghttp3_conn_read_stream2
// (pseudo-header order, presence and uniqueness; field-name syntax; the connection-specific
// fields; content-length arithmetic; `:status`), and what it rejects comes back as a negative
// read -- by the library's contract a CONNECTION error, after which only nghttp3_conn_del is
// legal. The adapter's validator runs in the callbacks nghttp3 fires for what it accepted: the
// field count, the field-value length limit, the request method, the trailer section's own rules.
// Those used to fail their callback, which fails the read the same way, so every exchange
// multiplexed on the connection went down with the malformed one. They refuse the STREAM now.
//
// The frames below are what a peer that skipped validation would send (the adapter itself refuses
// to SEND every one of them: SubmitRequestRejects* above). Each refusal case asserts four things
// -- the message never reaches the owner, the owner recorded no connection close, the stream was
// reset with H3_MESSAGE_ERROR, the next request on the SAME connection is served -- and fails
// against the previous code, where the close is recorded. The last case pins the other tier: a
// malformation nghttp3 rejects closes the connection with the H3 error code nghttp3 infers
// (H3_MESSAGE_ERROR), where the raw library code used to go on the wire.

namespace {

// The refusal's four assertions on the server side, then the follow-up request on stream 4.
void
expect_server_refused_stream_and_serves_next(Pair &pair, std::size_t states_before) {
    EXPECT_TRUE(pair.server_owner.requests.empty()) << "a malformed request must never reach the owner";
    EXPECT_FALSE(pair.server_owner.close.has_value())
        << "the connection must survive a malformed stream; closed with " << (pair.server_owner.close ? pair.server_owner.close->second : "");
    ASSERT_EQ(pair.server_owner.resets.size(), 1u) << "exactly one stream reset";
    EXPECT_EQ(pair.server_owner.resets.front().first, 0u);
    EXPECT_EQ(pair.server_owner.resets.front().second, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR));
    // The transport reports the reset stream closed: its state goes with it.
    pair.server.close_stream(0, NGHTTP3_H3_MESSAGE_ERROR);
    EXPECT_EQ(pair.server.stream_state_count(), states_before);
    // The next request on the SAME connection is decoded and served.
    qb::http::Request next{qb::http::method::GET, qb::io::uri("https://example.test/next")};
    ASSERT_TRUE(pair.client.submit_request(4, next));
    pair.settle();
    ASSERT_EQ(pair.server_owner.requests.size(), 1u) << "the connection no longer serves";
    EXPECT_EQ(pair.server_owner.requests.front().uri().path(), "/next");
    EXPECT_FALSE(pair.server_owner.close.has_value());
}

} // namespace

/**
 * @test A request over MAX_HEADERS_COUNT regular fields is answered 431; one at the limit is served
 * @brief nghttp3 has no field-count limit, so recv_header_cb's count is the only one, of REGULAR fields
 *        as HTTP/1.1 and HTTP/2 count them (the pseudo-headers are the request line): 101 are answered
 *        431 once the section ends -- STOP_SENDING(H3_NO_ERROR), no reset, the connection kept (Huly
 *        QB-94: the default limits are the server's too; it was a reset until 3.3) -- and a request of
 *        exactly 100 on the same connection is decoded whole. The limit, in both polarities.
 */
TEST(Http3ConnectionDirect, TooManyRequestHeaderFieldsAreAnswered431NotTheConnection) {
    Pair pair;
    auto fields = request_fields();
    for (std::size_t i = 0; i < qb::http::protocol_limits::MAX_HEADERS_COUNT + 1; ++i) {
        fields.emplace_back("x-" + std::to_string(i), "v");
    }
    pair.server.read_stream(0, h3_headers_frame(0, fields), true);
    EXPECT_TRUE(pair.server_owner.requests.empty()) << "a refused request must never reach the owner";
    EXPECT_TRUE(stopped_without_error(pair.server_owner, 0)) << "answered, then asked to stop without an error";
    EXPECT_FALSE(reset(pair.server_owner, 0));
    EXPECT_FALSE(pair.server_owner.close.has_value());

    // The positive control: exactly the limit, on the same connection, is served whole.
    auto at_limit = request_fields("/at-limit");
    for (std::size_t i = 0; i < qb::http::protocol_limits::MAX_HEADERS_COUNT; ++i) {
        at_limit.emplace_back("x-" + std::to_string(i), "v");
    }
    pair.server.read_stream(8, h3_headers_frame(8, at_limit), true);
    ASSERT_EQ(pair.server_owner.requests.size(), 1u);
    EXPECT_EQ(pair.server_owner.requests.back().uri().path(), "/at-limit");
    EXPECT_TRUE(pair.server_owner.resets.empty()) << "a request at the limit is not refused";
    EXPECT_FALSE(pair.server_owner.close.has_value());
}

/**
 * @test A field value over MAX_HEADER_VALUE_LENGTH is answered 431
 * @brief nghttp3 checks the value's bytes and caps one field with a connection error -- a value at 64 KiB and a
 *        name at 256 bytes, bounded by the length they decode to, which for a Huffman-coded string it takes as 8/5 of
 *        its encoded length (1.18.0 measured: 46811 'v' pass, 46812 do not; a Huffman name fails from 214 bytes) --,
 *        never a value's length below that: the request limits, and the 64 KiB field section this module bounds itself
 *        (nghttp3 does not, Huly QB-1196), are the only ones.
 *        (A NAME over this module's limit never gets here.) The request is answered 431 once its section ends
 *        -- STOP_SENDING(H3_NO_ERROR), no reset, the connection kept (Huly QB-94; a reset until 3.3) --
 *        and the next request on the connection is served.
 */
TEST(Http3ConnectionDirect, AnOverLongRequestFieldValueIsAnswered431NotTheConnection) {
    Pair pair;
    auto fields = request_fields();
    fields.emplace_back("x-big", std::string(qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'v'));
    fields.emplace_back("x-after", "2");
    pair.server.read_stream(0, h3_headers_frame(0, fields), true);
    EXPECT_TRUE(pair.server_owner.requests.empty()) << "a refused request must never reach the owner";
    EXPECT_TRUE(stopped_without_error(pair.server_owner, 0));
    EXPECT_FALSE(reset(pair.server_owner, 0));
    EXPECT_FALSE(pair.server_owner.close.has_value());

    pair.server.read_stream(4, h3_headers_frame(4, request_fields("/next")), true);
    ASSERT_EQ(pair.server_owner.requests.size(), 1u) << "the connection serves the next request";
}

/**
 * @test A request method this module does not know refuses the stream only
 * @brief nghttp3 accepts any token as `:method`; materialize_headers maps it to qb::http::Method and an
 *        unknown token is UNINITIALIZED -- the block fails in end_headers_cb, the stream is reset, the
 *        connection kept.
 */
TEST(Http3ConnectionDirect, AnUnknownRequestMethodRefusesTheStreamNotTheConnection) {
    Pair       pair;
    const auto states     = pair.server.stream_state_count();
    auto       fields     = request_fields();
    fields.front().second = "FETCH";
    pair.server.read_stream(0, h3_headers_frame(0, fields), true);
    expect_server_refused_stream_and_serves_next(pair, states);
}

/**
 * @test The request's URI is the one :scheme, :authority and :path name, its authority :authority's
 * @brief A `//evil.test/x` :path stays a path under `example.test`, an OPTIONS `*` is the URI `*`, a `host` field
 *        naming :authority is accepted (Huly QB-1177). `[`, `]` and `|`, which a browser sends as they are, stay in
 *        the path as they were sent (Huly QB-1187).
 */
TEST(Http3ConnectionDirect, TheTargetPseudoHeadersNameTheRequestUri) {
    {
        Pair pair;
        pair.server.read_stream(0, h3_headers_frame(0, request_fields("//evil.test/x")), true);
        pair.settle();
        ASSERT_EQ(pair.server_owner.requests.size(), 1u);
        auto const &uri = pair.server_owner.requests.front().uri();
        EXPECT_EQ(uri.host(), "example.test");
        EXPECT_TRUE(uri.user_info().empty());
        EXPECT_EQ(uri.path(), "//evil.test/x");
    }
    {
        Pair pair;
        pair.server.read_stream(0, h3_headers_frame(0, request_fields("/a|b/[c]?k=[v]|w")), true);
        pair.settle();
        ASSERT_EQ(pair.server_owner.requests.size(), 1u);
        auto const &uri = pair.server_owner.requests.front().uri();
        EXPECT_EQ(uri.host(), "example.test");
        EXPECT_EQ(uri.path(), "/a|b/[c]");
        EXPECT_EQ(uri.query("k"), "[v]|w");
    }
    {
        // The asterisk-form of an OPTIONS request: the URI `*`. Composed by hand, it was the host `example.test*`.
        auto fields           = request_fields("*");
        fields.front().second = "OPTIONS";
        Pair pair;
        pair.server.read_stream(0, h3_headers_frame(0, fields), true);
        pair.settle();
        ASSERT_EQ(pair.server_owner.requests.size(), 1u);
        EXPECT_EQ(pair.server_owner.requests.front().uri().path(), "*");
        EXPECT_TRUE(pair.server_owner.requests.front().uri().host().empty());
    }
    {
        // A `host` field that names :authority, in another case: the same authority.
        auto fields = request_fields();
        fields.emplace_back("host", "EXAMPLE.test");
        Pair pair;
        pair.server.read_stream(0, h3_headers_frame(0, fields), true);
        pair.settle();
        ASSERT_EQ(pair.server_owner.requests.size(), 1u);
        EXPECT_EQ(pair.server_owner.requests.front().uri().host(), "example.test");
    }
}

/**
 * @test A :path, :authority or :scheme that names no target never reaches the server
 * @brief Composed onto `example.test`, the :path `@evil.test/x` named the host evil.test, and a path byte the URI
 *        parser refuses left the request at the empty path (Huly QB-1177). nghttp3 (1.18.0) refuses the first shapes
 *        itself, a connection error; the others pass it, and qbm-http refuses their stream.
 */
TEST(Http3ConnectionDirect, AMalformedTargetPseudoHeaderNeverReachesTheServer) {
    using Fields = std::vector<std::pair<std::string, std::string>>;
    auto with    = [](std::string const &name, std::string value) {
        auto fields = request_fields();
        for (auto &[field, field_value] : fields)
            if (field == name)
                field_value = std::move(value);
        return fields;
    };
    auto with_host = [](std::vector<std::string> hosts) {
        auto fields = request_fields();
        for (auto &host : hosts)
            fields.emplace_back("host", std::move(host));
        return fields;
    };
    auto trace_of = [](Fields const &fields) {
        std::string trace;
        for (auto const &[name, value] : fields)
            trace += name + ": " + value + "; ";
        return trace;
    };
    // What nghttp3 refuses itself -- 1.18.0 measured: a connection error -- and qbm-http refuses next: whichever layer
    // does, with H3_MESSAGE_ERROR, and the request never reaches the owner. nghttp3 is a system library, not pinned.
    for (Fields const &fields :
         {with(":path", "@evil.test/x"), with(":path", "evil.test/x"), with(":authority", "user@example.test"),
          with(":authority", "example.test/evil"), with(":scheme", "ht/tps"), with_host({"example.test", "example.test"})}) {
        SCOPED_TRACE(trace_of(fields));
        Pair pair;
        pair.server.read_stream(0, h3_headers_frame(0, fields), true);
        EXPECT_TRUE(pair.server_owner.requests.empty()) << "a malformed request must never reach the owner";
        const auto message_error = static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR);
        const bool by_nghttp3    = pair.server_owner.close.has_value() && pair.server_owner.close->first == message_error;
        const bool by_qbm_http   = !pair.server_owner.close.has_value() && pair.server_owner.resets.size() == 1u
                                   && pair.server_owner.resets.front().second == message_error;
        EXPECT_TRUE(by_nghttp3 || by_qbm_http) << "refused by neither layer with H3_MESSAGE_ERROR";
    }
    // What nghttp3 lets through, qbm-http refuses on the stream: a path byte the URI parser refuses, an :authority that
    // is no authority, a `host` field that names another authority (RFC 9114 §4.3.1).
    for (Fields const &fields :
         {with(":path", "/a^b"), with(":path", "/a\\b"), with(":path", "/a{b}"), with(":authority", "a:b:c"),
          with(":authority", "example.test:99999"), with(":authority", "evil]"), with_host({"evil.test"})}) {
        SCOPED_TRACE(trace_of(fields));
        Pair       pair;
        const auto states = pair.server.stream_state_count();
        pair.server.read_stream(0, h3_headers_frame(0, fields), true);
        expect_server_refused_stream_and_serves_next(pair, states);
    }
}

/**
 * @test Without :authority, the one `host` field names the request's authority
 * @brief RFC 9114 section 4.3.1: a request for a scheme with a mandatory authority carries an :authority or a Host
 *        field. The request's URI is the one the same value sent as :authority composes (origin::request_uri()),
 *        and header("Host") gives it. nghttp3 lets such a request through; the server required :authority and
 *        refused every such stream (Huly QB-1195).
 */
TEST(Http3ConnectionDirect, AHostFieldNamesTheAuthorityOfARequestWithoutOne) {
    using Fields = std::vector<std::pair<std::string, std::string>>;
    struct Named {
        std::string method, scheme, authority, path;
    };
    auto serve = [](Fields const &fields) -> std::optional<qb::http::Request> {
        Pair pair;
        pair.server.read_stream(0, h3_headers_frame(0, fields), true);
        pair.settle();
        EXPECT_FALSE(pair.server_owner.close.has_value());
        EXPECT_TRUE(pair.server_owner.resets.empty());
        if (pair.server_owner.requests.size() != 1u)
            return std::nullopt;
        return pair.server_owner.requests.front();
    };
    for (auto const &c :
         {Named{"GET", "https", "example.test", "/h?x=1"}, Named{"GET", "http", "EXAMPLE.Test", "/h"},
          Named{"GET", "https", "example.test:8443", "//evil.test/x"}, Named{"GET", "https", "[2001:db8::1]:8443", "/v6"},
          Named{"GET", "http", "127.0.0.1:80", "/v4"}, Named{"OPTIONS", "https", "example.test", "*"},
          Named{"POST", "https", "example.test:", "/empty-port"}}) {
        SCOPED_TRACE(c.method + " " + c.scheme + " " + c.authority + " " + c.path);
        const auto by_authority = serve({{":method", c.method}, {":scheme", c.scheme}, {":authority", c.authority}, {":path", c.path}});
        const auto by_host      = serve({{":method", c.method}, {":scheme", c.scheme}, {":path", c.path}, {"x-a", "1"}, {"host", c.authority}});
        ASSERT_TRUE(by_authority.has_value()) << "the control: the value sent as :authority is served";
        ASSERT_TRUE(by_host.has_value()) << "the request naming its authority in its host field is served";
        EXPECT_EQ(by_host->header("Host"), c.authority);
        EXPECT_EQ(by_host->method(), by_authority->method());
        EXPECT_EQ(by_host->uri().source(), by_authority->uri().source());
        EXPECT_EQ(by_host->uri().scheme(), by_authority->uri().scheme());
        EXPECT_EQ(by_host->uri().host(), by_authority->uri().host());
        EXPECT_EQ(by_host->uri().port(), by_authority->uri().port());
        EXPECT_EQ(by_host->uri().path(), by_authority->uri().path());
        EXPECT_TRUE(by_host->uri().user_info().empty());
    }
}

/**
 * @test A request that names no authority, or names it in a `host` field that is no authority, never reaches the server
 * @brief Neither :authority nor `host`, an empty :authority, a `host` field that is no authority, a second `host`
 *        field: malformed (RFC 9114 section 4.3.1, Huly QB-1195). nghttp3 (1.18.0) refuses the first shapes itself,
 *        a connection error; the others pass it -- an authority its character check admits -- and qbm-http refuses
 *        their stream.
 */
TEST(Http3ConnectionDirect, ARequestWithoutAnAuthorityNeverReachesTheServer) {
    using Fields   = std::vector<std::pair<std::string, std::string>>;
    auto with_host = [](std::vector<std::string> hosts) {
        Fields fields{{":method", "GET"}, {":scheme", "https"}, {":path", "/h"}};
        for (auto &host : hosts)
            fields.emplace_back("host", std::move(host));
        return fields;
    };
    auto trace_of = [](Fields const &fields) {
        std::string trace;
        for (auto const &[name, value] : fields)
            trace += name + ": " + value + "; ";
        return trace;
    };
    // What nghttp3 refuses itself -- 1.18.0 measured: a connection error -- and qbm-http refuses next: whichever layer
    // does, with H3_MESSAGE_ERROR, and the request never reaches the owner. nghttp3 is a system library, not pinned.
    for (Fields const &fields :
         {with_host({}), Fields{{":method", "OPTIONS"}, {":scheme", "https"}, {":path", "*"}},
          Fields{{":method", "GET"}, {":scheme", "urn"}, {":path", "/h"}},
          Fields{{":method", "GET"}, {":scheme", "https"}, {":authority", ""}, {":path", "/h"}},
          Fields{{":method", "GET"}, {":scheme", "https"}, {":authority", ""}, {":path", "/h"}, {"host", ""}},
          Fields{{":method", "GET"}, {":scheme", "https"}, {":authority", ""}, {":path", "/h"}, {"host", "example.test"}}, with_host({""}),
          with_host({"user@example.test"}), with_host({"example.test/evil"}), with_host({"example.test, evil.test"}),
          with_host({"example.test", "example.test"}), with_host({"example.test", "evil.test"})}) {
        SCOPED_TRACE(trace_of(fields));
        Pair pair;
        pair.server.read_stream(0, h3_headers_frame(0, fields), true);
        EXPECT_TRUE(pair.server_owner.requests.empty()) << "a malformed request must never reach the owner";
        const auto message_error = static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR);
        const bool by_nghttp3    = pair.server_owner.close.has_value() && pair.server_owner.close->first == message_error;
        const bool by_qbm_http   = !pair.server_owner.close.has_value() && pair.server_owner.resets.size() == 1u
                                   && pair.server_owner.resets.front().second == message_error;
        EXPECT_TRUE(by_nghttp3 || by_qbm_http) << "refused by neither layer with H3_MESSAGE_ERROR";
    }
    // What nghttp3 lets through, qbm-http refuses on the stream: a `host` field that is no authority
    // (origin::is_request_authority(): no host, a port that is none, an IP literal that is no IPv6 address).
    for (Fields const &fields :
         {with_host({":443"}), with_host({"a:b:c"}), with_host({"example.test:99999"}), with_host({"evil]"}), with_host({"[127.0.0.1]"})}) {
        SCOPED_TRACE(trace_of(fields));
        Pair       pair;
        const auto states = pair.server.stream_state_count();
        pair.server.read_stream(0, h3_headers_frame(0, fields), true);
        expect_server_refused_stream_and_serves_next(pair, states);
    }
}

/**
 * @test A `trailer` field inside the trailer section refuses the stream only
 * @brief A second HEADERS frame after the body is the trailer section. nghttp3 drops a `content-length`
 *        there and rejects a pseudo-header, but has no rule for `trailer` itself; is_forbidden_h3_trailer
 *        does, so materialize_trailers fails in end_trailers_cb: the stream is reset, the connection kept.
 */
TEST(Http3ConnectionDirect, ATrailerFieldInsideTheTrailerSectionRefusesTheStreamNotTheConnection) {
    Pair       pair;
    const auto states     = pair.server.stream_state_count();
    auto       fields     = request_fields();
    fields.front().second = "POST";
    pair.server.read_stream(0, h3_headers_frame(0, fields), false);
    pair.server.read_stream(0, h3_data_frame("abc"), false);
    pair.server.read_stream(0, h3_headers_frame(0, {{"trailer", "x-t"}}), true);
    expect_server_refused_stream_and_serves_next(pair, states);
}

/**
 * @test A routing or request-modifier field in the trailer section refuses the stream only
 * @brief `host`, `te` and proxy authentication are in the one trailer list HTTP/1.1, HTTP/2 and HTTP/3
 *        share (qb::http::detail::is_forbidden_trailer_field); HTTP/3 accepted `host` and `te` there,
 *        and merged them into the request (Huly QB-1073). The stream is reset, the connection kept.
 */
TEST(Http3ConnectionDirect, ARoutingFieldInsideTheTrailerSectionRefusesTheStreamNotTheConnection) {
    for (const char *name : {"host", "te", "proxy-authorization"}) {
        SCOPED_TRACE(name);
        Pair       pair;
        const auto states     = pair.server.stream_state_count();
        auto       fields     = request_fields();
        fields.front().second = "POST";
        pair.server.read_stream(0, h3_headers_frame(0, fields), false);
        pair.server.read_stream(0, h3_data_frame("abc"), false);
        pair.server.read_stream(0, h3_headers_frame(0, {{name, "trailers"}}), true);
        expect_server_refused_stream_and_serves_next(pair, states);
    }
}

/**
 * @test An over-long response field refuses the stream on the CLIENT side, and the client keeps its connection
 * @brief The client submits a request; a response block with a value over MAX_HEADER_VALUE_LENGTH fails
 *        recv_header_cb in the client role. The response never reaches the owner, the client resets its
 *        stream with H3_MESSAGE_ERROR instead of closing the connection, and a second request on the same
 *        connection is answered normally.
 */
TEST(Http3ConnectionDirect, AnOverLongResponseFieldRefusesTheStreamNotTheConnection) {
    Pair       pair;
    const auto states = pair.client.stream_state_count();

    qb::http::Request first{qb::http::method::GET, qb::io::uri("https://example.test/first")};
    ASSERT_TRUE(pair.client.submit_request(0, first));
    pair.settle();
    ASSERT_EQ(pair.server_owner.requests.size(), 1u);

    pair.client.read_stream(
        0, h3_headers_frame(0, {{":status", "200"}, {"x-big", std::string(qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'v')}}),
        true);
    EXPECT_TRUE(pair.client_owner.responses.empty()) << "a malformed response must never reach the owner";
    EXPECT_FALSE(pair.client_owner.close.has_value()) << "the client's connection must survive a malformed response";
    ASSERT_EQ(pair.client_owner.resets.size(), 1u);
    EXPECT_EQ(pair.client_owner.resets.front().first, 0u);
    EXPECT_EQ(pair.client_owner.resets.front().second, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR));
    pair.client.close_stream(0, NGHTTP3_H3_MESSAGE_ERROR);
    EXPECT_EQ(pair.client.stream_state_count(), states);

    // A second exchange on the SAME client connection, answered by the real server side.
    qb::http::Request second{qb::http::method::GET, qb::io::uri("https://example.test/second")};
    ASSERT_TRUE(pair.client.submit_request(4, second));
    pair.settle();
    ASSERT_EQ(pair.server_owner.requests.size(), 2u);
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = "second";
    ASSERT_TRUE(pair.server.submit_response(4, response));
    pair.settle();
    ASSERT_EQ(pair.client_owner.responses.size(), 1u) << "the client's connection no longer serves";
    EXPECT_EQ(pair.client_owner.responses.front().status(), qb::http::status::OK);
    EXPECT_EQ(pair.client_owner.responses.front().body().template as<std::string>(), "second");
    EXPECT_FALSE(pair.client_owner.close.has_value());
}

/**
 * @test A malformation nghttp3 itself rejects closes the connection with H3_MESSAGE_ERROR on the wire
 * @brief The other tier. A body shorter than its content-length (nghttp3_http_on_remote_end_stream) and a
 *        regular field ahead of the pseudo-headers (nghttp3_http_on_header) never reach this adapter's
 *        callbacks: nghttp3_conn_read_stream2 returns NGHTTP3_ERR_MALFORMED_HTTP_MESSAGING / _HEADER,
 *        by contract a connection error. The close the owner receives carries the H3 error code nghttp3
 *        infers, H3_MESSAGE_ERROR -- the raw library codes (107, 105) used to be sent as the application
 *        error code -- and the request was never delivered. (A field name over 256 bytes is a third
 *        case of this tier, refused by nghttp3's QPACK decoder before any HTTP rule.)
 */
TEST(Http3ConnectionDirect, AMalformationNghttp3RejectsClosesTheConnectionWithMessageError) {
    {
        Pair pair;
        auto fields           = request_fields();
        fields.front().second = "POST";
        fields.emplace_back("content-length", "5");
        pair.server.read_stream(0, h3_headers_frame(0, fields), false);
        EXPECT_FALSE(pair.server.read_stream(0, h3_data_frame("abc"), true)) << "the read reports the connection error";
        EXPECT_TRUE(pair.server_owner.requests.empty());
        ASSERT_TRUE(pair.server_owner.close.has_value()) << "nghttp3's own rejection is a connection error by contract";
        EXPECT_EQ(pair.server_owner.close->first, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR)) << "the inferred H3 code, not 107";
        EXPECT_EQ(pair.server_owner.close->second, "HTTP/3 protocol read error");
    }
    {
        Pair pair;
        auto fields = request_fields();
        fields.insert(fields.begin(), {"x-first", "1"}); // a regular field ahead of the pseudo-headers
        EXPECT_FALSE(pair.server.read_stream(0, h3_headers_frame(0, fields), true));
        EXPECT_TRUE(pair.server_owner.requests.empty());
        ASSERT_TRUE(pair.server_owner.close.has_value());
        EXPECT_EQ(pair.server_owner.close->first, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR)) << "the inferred H3 code, not 105";
    }
}

// =============================================================================
// GRACEFUL SHUTDOWN — submit_shutdown_notice / shutdown / is_drained / shutdown_cb
// =============================================================================

/**
 * @test submit_shutdown_notice emits a GOAWAY that the peer observes via shutdown_cb
 * @brief The server submits a shutdown NOTICE (GOAWAY without tearing down); pumping the control-stream
 *        bytes to the client drives nghttp3's shutdown callback -> on_http3_shutdown on the client owner.
 */
TEST(Http3ConnectionDirect, ShutdownNoticeReachesPeerAsGoaway) {
    Pair pair;

    EXPECT_TRUE(pair.server.submit_shutdown_notice());
    pair.settle();

    EXPECT_FALSE(pair.client_owner.shutdowns.empty()) << "the client should observe the server's GOAWAY";
}

/**
 * @test shutdown() marks the connection draining and is_drained() reports completion
 * @brief Before shutdown, is_drained() is false. After shutdown() (and pumping the GOAWAY), the
 *        connection reports started-and-drained once nghttp3 considers it fully drained, so the
 *        transport may safely close. Asserts the documented is_drained gate (false before, true after).
 */
TEST(Http3ConnectionDirect, ShutdownThenDrainedGateReportsCompletion) {
    Pair pair;

    EXPECT_FALSE(pair.server.is_drained()) << "is_drained must be false before shutdown is started";

    EXPECT_TRUE(pair.server.shutdown());
    pair.settle();

    // With no in-flight requests, a shutdown connection drains immediately.
    EXPECT_TRUE(pair.server.is_drained()) << "a quiescent connection must report drained after shutdown()";
}

// =============================================================================
// MOVE — a moved connection is the connection (Huly QB-502)
// =============================================================================

/**
 * @test A connection moved outside every native call keeps its nghttp3 identity and its state
 * @brief nghttp3 calls back with the user data it was given at creation, and offers no way to change
 *        it, so the identity it holds must not be the address of the object that moves. The client is
 *        bound, moved, and its source destroyed; binding again must be the documented no-op (the
 *        streams are already bound), and a full request/response exchange must run through the
 *        destination -- under ASan, any callback still reaching the destroyed source is a
 *        heap-use-after-free.
 */
TEST(Http3ConnectionDirect, AMovedConnectionKeepsItsNativeIdentityAndBindings) {
    ClientOwner      client_owner;
    ServerOwner      server_owner;
    ServerConnection server{server_owner, 1, ServerConnection::role::server};
    ASSERT_TRUE(server.bind_local_streams());
    auto source = std::make_unique<ClientConnection>(client_owner, 1, ClientConnection::role::client);
    ASSERT_TRUE(source->bind_local_streams());
    const auto opened = client_owner.next_uni;

    ClientConnection client{std::move(*source)};
    source.reset();
    ASSERT_TRUE(client.ok());
    EXPECT_TRUE(client.bind_local_streams()) << "the streams were bound before the move";
    EXPECT_EQ(client_owner.next_uni, opened) << "a moved connection must not open its control streams a second time";
    pump(client_owner, client, server_owner, server);

    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/after-move")};
    ASSERT_TRUE(client.submit_request(0, request));
    pump(client_owner, client, server_owner, server);
    ASSERT_EQ(server_owner.requests.size(), 1u);
    EXPECT_EQ(server_owner.requests.front().uri().path(), "/after-move");

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = "answered after the move";
    ASSERT_TRUE(server.submit_response(0, response));
    pump(client_owner, client, server_owner, server);
    ASSERT_EQ(client_owner.responses.size(), 1u);
    EXPECT_EQ(client_owner.responses.front().body().template as<std::string>(), "answered after the move");
    EXPECT_FALSE(client_owner.close.has_value()) << (client_owner.close ? client_owner.close->second : std::string{});
}

/**
 * @test The shutdown state travels with a move
 * @brief A server connection that started its graceful shutdown before being moved must still report
 *        drained once the peer has the GOAWAY: `is_drained()` gates the transport close.
 */
TEST(Http3ConnectionDirect, AMovedConnectionKeepsItsShutdownState) {
    ClientOwner      client_owner;
    ServerOwner      server_owner;
    ClientConnection client{client_owner, 1, ClientConnection::role::client};
    ASSERT_TRUE(client.bind_local_streams());
    auto source = std::make_unique<ServerConnection>(server_owner, 1, ServerConnection::role::server);
    ASSERT_TRUE(source->bind_local_streams());
    pump(client_owner, client, server_owner, *source);
    ASSERT_TRUE(source->shutdown());

    ServerConnection server{std::move(*source)};
    source.reset();
    pump(client_owner, client, server_owner, server);
    EXPECT_TRUE(server.is_drained()) << "a shutdown started before the move must be seen through to drained";
    EXPECT_FALSE(client_owner.shutdowns.empty()) << "the GOAWAY reached the peer";
}

// =============================================================================
// :authority — an IPv6 literal keeps its brackets (Huly QB-572)
// =============================================================================

/**
 * @test An IPv6 literal host is bracketed in :authority and reaches the server as the same origin
 * @brief RFC 3986 section 3.2.2 writes an IP-literal host between brackets, and RFC 9114 section
 *        4.3.1 carries the URI authority in :authority. The bare `::1:8443` the builder used to emit is
 *        not an authority; the server, rebuilding the request URI from it, could not recover the host.
 */
TEST(Http3ConnectionDirect, IPv6AuthorityKeepsItsBracketsEndToEnd) {
    Pair          pair;
    std::uint64_t stream = 0;
    struct case_t {
        std::string target, host, port, received;
    };
    for (auto const &[target, host, port, received] : std::vector<case_t>{
             {"https://[::1]:8443/v6?q=1", "::1", "8443", "https://[::1]:8443/v6?q=1"},
             // The scheme's default port is not sent (qb::http::origin::authority, Huly QB-1064): the
             // server's URI fills it in again, its source text names none.
             {"https://[2001:db8::7]/v6", "2001:db8::7", "443", "https://[2001:db8::7]/v6"}
         }) {
        qb::http::Request request{qb::http::method::GET, qb::io::uri(target)};
        ASSERT_EQ(request.uri().host(), host) << "the client side parses the literal without its brackets";
        ASSERT_TRUE(pair.client.submit_request(stream, request)) << target;
        pair.settle();
        ASSERT_EQ(pair.server_owner.requests.size(), stream / 4 + 1) << target;
        auto const &got = pair.server_owner.requests.back();
        // The server rebuilds the URI from :scheme, :authority and :path: its source is the authority as received.
        EXPECT_EQ(got.uri().source(), received) << "the :authority on the wire was not the URI's authority";
        EXPECT_EQ(got.uri().host(), host) << target;
        EXPECT_EQ(got.uri().port(), port) << target;
        EXPECT_EQ(got.uri().path(), "/v6") << target;
        stream += 4;
    }
    EXPECT_FALSE(pair.server_owner.close.has_value());
}

// =============================================================================
// ACK OFFSET — add_ack_offset zero is a no-op; non-zero is accepted
// =============================================================================

/**
 * @test add_ack_offset is a no-op for zero bytes and accepted for a real ack
 * @brief add_ack_offset(stream, 0) short-circuits without touching nghttp3 (the documented zero-count
 *        no-op); a non-zero ack on a live request stream is accepted without error. Driven after a real
 *        request is in flight so the stream exists in nghttp3's map.
 */
TEST(Http3ConnectionDirect, AddAckOffsetZeroIsNoopNonZeroAccepted) {
    Pair pair;

    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/x")};
    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();

    // Zero is a guarded no-op (no crash, no state change). Non-zero is accepted by nghttp3.
    pair.client.add_ack_offset(0, 0);
    pair.client.add_ack_offset(0, 1);
    SUCCEED(); // reaching here without an nghttp3 abort/throw is the assertion
}

/**
 * @test DATA arriving after a body limit refusal restores connection credit once
 * @brief After a refusal (a 413 and STOP_SENDING since 3.3, Huly QB-168; a reset before), nghttp3 may
 *        account later DATA in read_stream2 without another receive callback. The owner must receive
 *        exactly the wire byte count through that return value and the earlier callback credit together.
 */
TEST(Http3ConnectionDirect, RefusedStreamCreditsSubsequentDataOnce) {
    struct CappedServerOwner : ServerOwner {
        std::uint64_t
        max_http3_body_size() const noexcept {
            return 16;
        }
    };
    using CappedServerConnection = connection<CappedServerOwner>;

    CappedServerOwner      owner;
    CappedServerConnection server{owner, 1, CappedServerConnection::role::server};
    ASSERT_TRUE(server.bind_local_streams());

    const auto headers = h3_headers_frame(0, {{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/upload"}});
    const auto first   = h3_data_frame(std::string(64, 'B'));
    const auto second  = h3_data_frame(std::string(32, 'C'));
    ASSERT_TRUE(server.read_stream(0, headers, false));
    ASSERT_TRUE(server.read_stream(0, first, false));
    ASSERT_TRUE(server.read_stream(0, second, false));

    EXPECT_TRUE(owner.resets.empty()) << "the request is answered, not reset";
    ASSERT_EQ(owner.stops.size(), 1u);
    EXPECT_EQ(owner.stops.front().first, 0u);
    EXPECT_TRUE(owner.requests.empty());
    EXPECT_EQ(owner.credit[0], headers.size() + first.size() + second.size());
}

// =============================================================================
// THE SERVER'S REQUEST LIMITS (Huly QB-94): A REQUEST OVER ONE IS ANSWERED, AS ON HTTP/1.1 AND HTTP/2
// =============================================================================
//
// An owner that exposes http3_request_limits() (the server, set_request_limits) has them applied to the
// field sections the connection reads: a `:path` over max_url_length is answered 414, a regular field's
// name or value over its limit, or a section with more regular fields than max_headers_count, 431 -- once
// the section is known well-formed -- then STOP_SENDING(H3_NO_ERROR), the connection kept. Each limit in
// both polarities: exactly at it, the request is served.

namespace {

struct LimitedServerOwner : ServerOwner {
    qb::http::request_limits limits;

    [[nodiscard]] qb::http::request_limits const &
    http3_request_limits() const noexcept {
        return limits;
    }
};
using LimitedServerConnection = connection<LimitedServerOwner>;

/// A client and a limited server, connected: requests go through the client, so the answer is decoded.
struct LimitedPair {
    ClientOwner             client_owner;
    LimitedServerOwner      server_owner;
    ClientConnection        client{client_owner, 1, ClientConnection::role::client};
    LimitedServerConnection server{server_owner, 1, LimitedServerConnection::role::server};

    explicit LimitedPair(qb::http::request_limits limits) {
        server_owner.limits = limits;
        EXPECT_TRUE(client.bind_local_streams());
        EXPECT_TRUE(server.bind_local_streams());
        pump(client_owner, client, server_owner, server);
    }

    /// Submits @p request on @p stream_id and runs the exchange.
    void
    exchange(std::uint64_t stream_id, qb::http::Request request) {
        ASSERT_TRUE(client.submit_request(stream_id, request));
        pump(client_owner, client, server_owner, server);
    }
};

qb::http::Request
get_to(std::string const &path) {
    return qb::http::Request{qb::http::method::GET, qb::io::uri("https://example.test" + path)};
}

/// The request on @p stream_id was answered @p status, then its read side stopped without an error.
void
expect_answered(LimitedPair const &pair, std::uint64_t stream_id, qb::http::Status status) {
    ASSERT_FALSE(pair.client_owner.responses.empty()) << "the client receives the answer";
    EXPECT_EQ(pair.client_owner.responses.back().status(), status);
    EXPECT_TRUE(stopped_without_error(pair.server_owner, stream_id)) << "the client is asked to stop sending, without an error";
    EXPECT_FALSE(reset(pair.server_owner, stream_id)) << "the request is answered, not reset";
    EXPECT_FALSE(pair.server_owner.close.has_value()) << "the connection survives";
}

} // namespace

TEST(Http3ConnectionDirect, ServerAnswersAPathOverItsLimitWith414) {
    qb::http::request_limits limits;
    limits.max_url_length = 16;
    LimitedPair pair{limits};

    pair.exchange(0, get_to("/" + std::string(15, 'a')));
    ASSERT_EQ(pair.server_owner.requests.size(), 1u) << "a :path of exactly 16 bytes is served";

    pair.exchange(4, get_to("/" + std::string(16, 'a')));
    EXPECT_EQ(pair.server_owner.requests.size(), 1u) << "a refused request is never delivered";
    expect_answered(pair, 4, qb::http::status::URI_TOO_LONG);
}

TEST(Http3ConnectionDirect, ServerAnswersFieldsOverTheLimitsWith431) {
    qb::http::request_limits limits;
    limits.max_header_name_length  = 8;
    limits.max_header_value_length = 8;
    limits.max_headers_count       = 2;
    LimitedPair pair{limits};

    auto at_limits = get_to("/at");
    at_limits.set_header("x-abcdef", "12345678");
    at_limits.set_header("x-b", "2");
    pair.exchange(0, at_limits);
    ASSERT_EQ(pair.server_owner.requests.size(), 1u) << "a name and a value of exactly 8 bytes, 2 fields: served";

    auto long_name = get_to("/");
    long_name.set_header("x-abcdefg", "1");
    pair.exchange(4, long_name);
    expect_answered(pair, 4, qb::http::status::REQUEST_HEADER_FIELDS_TOO_LARGE);

    auto long_value = get_to("/");
    long_value.set_header("x-v", "123456789");
    pair.exchange(8, long_value);
    expect_answered(pair, 8, qb::http::status::REQUEST_HEADER_FIELDS_TOO_LARGE);

    auto many = get_to("/");
    many.set_header("x-a", "1");
    many.set_header("x-b", "2");
    many.set_header("x-c", "3");
    pair.exchange(12, many);
    expect_answered(pair, 12, qb::http::status::REQUEST_HEADER_FIELDS_TOO_LARGE);

    EXPECT_EQ(pair.server_owner.requests.size(), 1u) << "no refused request is delivered";
    EXPECT_EQ(pair.client_owner.responses.size(), 3u);
}

// The trailer section is held to the same field limits, its count its own; the frames are sent raw, as a
// client that sends trailers would.
TEST(Http3ConnectionDirect, ServerAnswersATrailerSectionOverTheFieldLimitsWith431) {
    qb::http::request_limits limits;
    limits.max_headers_count = 2;
    LimitedPair pair{limits};

    auto fields      = request_fields("/upload");
    fields[0].second = "POST";
    pair.server.read_stream(0, h3_headers_frame(0, fields), false);
    pair.server.read_stream(0, h3_data_frame("abc"), false);
    pair.server.read_stream(0, h3_headers_frame(0, {{"x-a", "1"}, {"x-b", "2"}, {"x-c", "3"}}), true);
    EXPECT_TRUE(pair.server_owner.requests.empty());
    EXPECT_TRUE(stopped_without_error(pair.server_owner, 0));
    EXPECT_FALSE(reset(pair.server_owner, 0));
    EXPECT_FALSE(pair.server_owner.close.has_value());

    pair.server.read_stream(4, h3_headers_frame(4, fields), false);
    pair.server.read_stream(4, h3_data_frame("abc"), false);
    pair.server.read_stream(4, h3_headers_frame(4, {{"x-a", "1"}, {"x-b", "2"}}), true);
    ASSERT_EQ(pair.server_owner.requests.size(), 1u) << "2 trailer fields are at the limit";
}

// The `host` field that names the authority of a request without :authority is a field like any other: over the
// value limit, the request is answered 431 -- once it is known well-formed, as HTTP/2 answers it -- and a second
// `host` field stays malformed, counted over the limit or not (Huly QB-1195). nghttp3 (1.18.0) refuses a second
// `host` field itself, a connection error: either layer, one pair each.
TEST(Http3ConnectionDirect, AHostFieldThatStandsForTheAuthorityIsHeldToTheFieldLimits) {
    qb::http::request_limits limits;
    limits.max_header_value_length = 12;
    auto with_hosts                = [](std::vector<std::string> hosts) {
        std::vector<std::pair<std::string, std::string>> fields{{":method", "GET"}, {":scheme", "https"}, {":path", "/"}};
        for (auto &host : hosts)
            fields.emplace_back("host", std::move(host));
        return fields;
    };
    {
        LimitedPair pair{limits};
        pair.server.read_stream(0, h3_headers_frame(0, with_hosts({"example.test"})), true);
        ASSERT_EQ(pair.server_owner.requests.size(), 1u) << "a host of exactly the value limit is served";
        EXPECT_EQ(pair.server_owner.requests.front().uri().host(), "example.test");

        pair.server.read_stream(4, h3_headers_frame(4, with_hosts({"example.test:8"})), true);
        EXPECT_EQ(pair.server_owner.requests.size(), 1u) << "a refused request is never delivered";
        EXPECT_TRUE(stopped_without_error(pair.server_owner, 4)) << "answered 431, then asked to stop sending without an error";
        EXPECT_FALSE(reset(pair.server_owner, 4)) << "a well-formed host over the value limit is answered, not refused";
        EXPECT_FALSE(pair.server_owner.close.has_value());

        // Another field over the value limit, before or after the host: the request is answered 431, its host the
        // one authority it names -- a field dropped for the limits is counted as a `host` field only if it is one.
        auto fields = with_hosts({"example.test"});
        fields.emplace_back("x-v", "1234567890123");
        pair.server.read_stream(8, h3_headers_frame(8, fields), true);
        fields = with_hosts({});
        fields.emplace_back("x-v", "1234567890123");
        fields.emplace_back("host", "example.test");
        pair.server.read_stream(12, h3_headers_frame(12, fields), true);
        EXPECT_EQ(pair.server_owner.requests.size(), 1u);
        // Another field over the limits, then the host over them too: the host is still the first `host` field over
        // the limits, kept.
        fields = with_hosts({});
        fields.emplace_back("x-v", "1234567890123");
        fields.emplace_back("host", "example.test:8");
        pair.server.read_stream(20, h3_headers_frame(20, fields), true);
        for (std::uint64_t stream_id : {8u, 12u, 20u}) {
            EXPECT_TRUE(stopped_without_error(pair.server_owner, stream_id)) << stream_id << " answered 431";
            EXPECT_FALSE(reset(pair.server_owner, stream_id)) << stream_id << " answered, not refused";
        }
        EXPECT_FALSE(pair.server_owner.close.has_value());

        // A `host` over the limits beside :authority that names it: a field over the limits like any other, 431.
        pair.server.read_stream(
            24,
            h3_headers_frame(
                24, {{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test:8"}, {":path", "/"}, {"host", "example.test:8"}}),
            true);
        EXPECT_TRUE(stopped_without_error(pair.server_owner, 24)) << "answered 431";
        EXPECT_FALSE(reset(pair.server_owner, 24));
    }
    // A malformed request beside the limits stays malformed, its stream refused, never answered 431 (Huly QB-1195): a
    // `host` that is no authority (nghttp3 lets `example.test:99999` through), a `host` over the limits that names
    // another authority than :authority -- kept for that check, it was dropped and answered 431 unread --, a :path
    // that is no absolute path beside a field over the limits.
    for (auto const &fields : std::vector<std::vector<std::pair<std::string, std::string>>>{
             {{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"host", "example.test:99999"}},
             {{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/"}, {"host", "evil.example.test"}},
             {{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/a^b"}, {"x-v", "1234567890123"}}
         }) {
        std::string trace;
        for (auto const &[name, value] : fields)
            trace += name + ": " + value + "; ";
        SCOPED_TRACE(trace);
        LimitedPair pair{limits};
        pair.server.read_stream(0, h3_headers_frame(0, fields), true);
        EXPECT_TRUE(pair.server_owner.requests.empty());
        EXPECT_FALSE(stopped_without_error(pair.server_owner, 0)) << "a malformed request is not answered";
        EXPECT_TRUE(reset(pair.server_owner, 0)) << "its stream is refused";
        EXPECT_FALSE(pair.server_owner.close.has_value()) << "the connection survives";
    }
    // In a trailer section, a `host` over the limits names no authority, and a trailer section must not carry one: the
    // stream is refused, as it is for a `host` within the limits there (Huly QB-1197; it was dropped and the request
    // answered 431).
    {
        LimitedPair                                      pair{limits};
        std::vector<std::pair<std::string, std::string>> fields{
            {":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/upload"}
        };
        pair.server.read_stream(0, h3_headers_frame(0, fields), false);
        pair.server.read_stream(0, h3_data_frame("abc"), false);
        pair.server.read_stream(0, h3_headers_frame(0, {{"host", "example.test:8"}}), true);
        EXPECT_TRUE(pair.server_owner.requests.empty());
        EXPECT_FALSE(stopped_without_error(pair.server_owner, 0)) << "a malformed request is not answered";
        EXPECT_TRUE(reset(pair.server_owner, 0)) << "its stream is refused";
        EXPECT_FALSE(pair.server_owner.close.has_value());
    }
    for (auto const &hosts :
         {std::vector<std::string>{"example.test", "example.test:8"}, std::vector<std::string>{"example.test:8", "example.test"},
          std::vector<std::string>{"example.test:8", "example.test:9"}}) {
        SCOPED_TRACE(hosts.front() + ", " + hosts.back());
        LimitedPair pair{limits};
        pair.server.read_stream(0, h3_headers_frame(0, with_hosts(hosts)), true);
        EXPECT_TRUE(pair.server_owner.requests.empty());
        EXPECT_FALSE(stopped_without_error(pair.server_owner, 0)) << "a malformed request is not answered";
        const auto message_error = static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR);
        const bool by_nghttp3    = pair.server_owner.close.has_value() && pair.server_owner.close->first == message_error;
        const bool by_qbm_http   = !pair.server_owner.close.has_value() && pair.server_owner.resets.size() == 1u
                                   && pair.server_owner.resets.front().second == message_error;
        EXPECT_TRUE(by_nghttp3 || by_qbm_http) << "refused by neither layer with H3_MESSAGE_ERROR";
    }
}

namespace {

/// Request limits of one kind tightened, the others left as they are: the name, the value, the field count, the target.
struct TightLimits {
    std::size_t name = 0, value = 0, count = 0, url = 0;

    [[nodiscard]] qb::http::request_limits
    limits() const {
        qb::http::request_limits l;
        if (name)
            l.max_header_name_length = name;
        if (value)
            l.max_header_value_length = value;
        if (count)
            l.max_headers_count = count;
        if (url)
            l.max_url_length = url;
        return l;
    }
};

/// The request on stream 0 was refused by this module, never answered nor delivered.
void
expect_refused_unanswered(LimitedPair const &pair) {
    EXPECT_TRUE(pair.server_owner.requests.empty());
    EXPECT_FALSE(stopped_without_error(pair.server_owner, 0)) << "a malformed request is not answered";
    ASSERT_EQ(pair.server_owner.resets.size(), 1u) << "its stream is refused";
    EXPECT_EQ(pair.server_owner.resets.front().second, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR));
}

} // namespace

// A `host` and a `content-length` over the request limits are judged when they arrive and dropped (Huly QB-1196): the
// host against :authority, or as an authority without it, the length as the number it declares -- kept as a count and a
// number. They were kept whole, up to nghttp3's 64 KiB a value, as long as the stream lived: the 431 answered, a
// request of 60 KB of `host` and 60 KB of zeros of `content-length` held 120 KB until the client closed its stream.
// The verdicts are unchanged: well-formed, answered 431; a host that is no authority without :authority, refused.
TEST(Http3ConnectionDirect, AHostAndAContentLengthOverTheLimitsAreJudgedWhenTheyArriveAndNotKept) {
    {
        qb::http::request_limits limits;
        limits.max_header_value_length = 12;
        LimitedPair pair{limits};
        pair.server.read_stream(
            0, h3_headers_frame(0, {{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"host", "example.test:99999"}}), true);
        EXPECT_TRUE(pair.server_owner.requests.empty());
        EXPECT_FALSE(stopped_without_error(pair.server_owner, 0)) << "a host that is no authority: refused, not answered";
        EXPECT_TRUE(reset(pair.server_owner, 0));
    }
#if !QBM_HTTP_TEST_HEAP_IN_USE
    GTEST_SKIP() << "the heap in use is measured with glibc's mallinfo2(), without a sanitizer's allocator";
#else
    const std::string                                      long_host(60000, 'a');
    const std::string                                      long_length(60000, '0');
    LimitedPair                                            pair{qb::http::request_limits{}};
    const std::vector<std::pair<std::string, std::string>> fields{
        {":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"host", long_host}, {"content-length", long_length}
    };
    const auto        frame  = h3_headers_frame(0, fields);
    const std::size_t before = mallinfo2().uordblks;
    pair.server.read_stream(0, frame, false); // the stream stays open: what its state keeps, it keeps
    const std::size_t after = mallinfo2().uordblks;
    EXPECT_TRUE(pair.server_owner.requests.empty());
    EXPECT_TRUE(stopped_without_error(pair.server_owner, 0)) << "well-formed: answered 431";
    EXPECT_FALSE(reset(pair.server_owner, 0));
    EXPECT_FALSE(pair.server_owner.close.has_value());
    const auto kept = static_cast<long long>(after) - static_cast<long long>(before);
    EXPECT_LT(kept, 32 * 1024) << "the stream keeps " << kept << " bytes: the 120 KB of the two fields are not among them";
#endif
}

// A stream that ends with its header section carries no body: a `content-length` that declares one makes the request
// malformed (RFC 9114 section 4.1.2), beside every limit, in both orders, and when the `content-length` field is itself
// the one over a limit -- refused, never answered 431 or 414 (Huly QB-1197: the length was judged at the end of the
// stream, after those answers, and a `content-length` over the limits was dropped unread). nghttp3 (1.18.0) then
// closes the connection for the mismatch, as it does within the limits; a `content-length` that is no number, or two,
// it refuses first. A `content-length: 0` beside a limit, and a `content-length: 5` whose body may still come, are
// well-formed: answered 431.
TEST(Http3ConnectionDirect, AContentLengthBesideTheLimitsIsJudgedFirst) {
    using Fields = std::vector<std::pair<std::string, std::string>>;
    const std::string over_value(9, 'v'); // over a value limit of 8
    const std::string over_name(17, 'n'); // over a name limit of 16
    auto              post = [](std::string path, Fields extra) {
        Fields f{{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", std::move(path)}};
        f.insert(f.end(), extra.begin(), extra.end());
        return f;
    };
    const std::vector<std::tuple<std::string, TightLimits, Fields>> shapes{
        {"value, before", {.value = 8}, post("/", {{"content-length", "5"}, {"x-v", over_value}})},
        {"value, after", {.value = 8}, post("/", {{"x-v", over_value}, {"content-length", "5"}})},
        {"name, before", {.name = 16}, post("/", {{"content-length", "5"}, {over_name, "1"}})},
        {"name, after", {.name = 16}, post("/", {{over_name, "1"}, {"content-length", "5"}})},
        {"count, before", {.count = 2}, post("/", {{"content-length", "5"}, {"x-a", "1"}, {"x-b", "2"}})},
        {"count, the content-length past it", {.count = 2}, post("/", {{"x-a", "1"}, {"x-b", "2"}, {"content-length", "5"}})},
        {"target", {.url = 8}, post("/" + std::string(16, 'p'), {{"content-length", "5"}})},
        {"the content-length over the value limit", {.value = 4}, post("/", {{"content-length", "00005"}})},
        {"the content-length over the name limit", {.name = 8}, post("/", {{"content-length", "5"}})},
    };
    for (auto const &[label, tight, fields] : shapes) {
        SCOPED_TRACE(label);
        LimitedPair pair{tight.limits()};
        pair.server.read_stream(0, h3_headers_frame(0, fields), true);
        expect_refused_unanswered(pair);
        if (pair.server_owner.close) {
            EXPECT_EQ(pair.server_owner.close->first, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR)) << "nghttp3's own verdict";
        }
    }

    // Well-formed beside the limits: answered -- a `content-length` over a limit itself included, kept and judged.
    {
        LimitedPair pair{TightLimits{.value = 8}.limits()};
        pair.server.read_stream(0, h3_headers_frame(0, post("/", {{"content-length", "0"}, {"x-v", over_value}})), true);
        pair.server.read_stream(4, h3_headers_frame(4, post("/", {{"content-length", "5"}, {"x-v", over_value}})), false);
        pair.server.read_stream(8, h3_headers_frame(8, post("/", {{"content-length", "000000000"}})), true);
        pair.server.read_stream(12, h3_headers_frame(12, post("/", {{"content-length", "000000005"}})), false);
        for (std::uint64_t stream_id : {0u, 4u, 8u, 12u}) {
            EXPECT_TRUE(stopped_without_error(pair.server_owner, stream_id)) << stream_id << " answered 431";
            EXPECT_FALSE(reset(pair.server_owner, stream_id)) << stream_id;
        }
        EXPECT_TRUE(pair.server_owner.requests.empty());
        EXPECT_FALSE(pair.server_owner.close.has_value());
    }
    // Where the stream's end comes in a later read than its header section, the request is not known malformed when the
    // section ends: answered 431 then, as HTTP/2 answers a HEADERS without END_STREAM. nghttp3 closes the connection
    // for the mismatch at the stream's end.
    {
        LimitedPair pair{TightLimits{.value = 8}.limits()};
        pair.server.read_stream(0, h3_headers_frame(0, post("/", {{"content-length", "5"}, {"x-v", over_value}})), false);
        pair.server.read_stream(0, "", true);
        EXPECT_TRUE(stopped_without_error(pair.server_owner, 0)) << "answered 431 when the section ended";
        EXPECT_TRUE(pair.server_owner.requests.empty());
        if (pair.server_owner.close) {
            EXPECT_EQ(pair.server_owner.close->first, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR));
        }
    }
}

// The same order before the body limit (Huly QB-1197): a `content-length` over the server's body cap on a stream that
// ends with its header section is a malformed request, refused, not answered 413 -- malformed before it is too large,
// as on HTTP/2 since QB-168.
TEST(Http3ConnectionDirect, AContentLengthTheEndedStreamContradictsIsMalformedBeforeTheBodyLimit) {
    ClientOwner            client_owner;
    CappedServerOwner      server_owner;
    ClientConnection       client{client_owner, 1, ClientConnection::role::client};
    CappedServerConnection server{server_owner, 1, CappedServerConnection::role::server};
    ASSERT_TRUE(client.bind_local_streams());
    ASSERT_TRUE(server.bind_local_streams());
    pump(client_owner, client, server_owner, server);
    auto fields      = request_fields("/upload");
    fields[0].second = "POST";
    fields.emplace_back("content-length", "64"); // over the 16-byte cap
    server.read_stream(0, h3_headers_frame(0, fields), true);
    EXPECT_TRUE(server_owner.requests.empty());
    EXPECT_FALSE(stopped_without_error(server_owner, 0)) << "a malformed request is not answered 413";
    ASSERT_EQ(server_owner.resets.size(), 1u);
    EXPECT_EQ(server_owner.resets.front().second, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR));
}

// The client reads a response the same way: a header section that ends the stream with a `content-length` it
// contradicts refuses the stream, as does a trailer section that ends a body its `content-length` contradicts; a HEAD
// response, or a 304, declares a length it does not carry (Huly QB-1197).
TEST(Http3ConnectionDirect, AResponseTheEndedStreamContradictsRefusesTheStream) {
    for (auto const &[method, status] : std::vector<std::pair<qb::http::Method, std::string>>{
             {qb::http::method::GET, "200"}, {qb::http::method::HEAD, "200"}, {qb::http::method::GET, "304"}
         }) {
        const bool exempt = method == qb::http::method::HEAD || status == "304";
        SCOPED_TRACE(std::string(method) + " " + status);
        Pair              pair;
        qb::http::Request request{method, qb::io::uri("https://example.test/r")};
        ASSERT_TRUE(pair.client.submit_request(0, request));
        pair.settle();
        pair.client.read_stream(0, h3_headers_frame(0, {{":status", status}, {"content-length", "5"}}), true);
        if (exempt) {
            ASSERT_EQ(pair.client_owner.responses.size(), 1u) << "a HEAD response, or a 304, declares a length it does not carry";
            EXPECT_TRUE(pair.client_owner.resets.empty());
        } else {
            EXPECT_TRUE(pair.client_owner.responses.empty());
            ASSERT_EQ(pair.client_owner.resets.size(), 1u);
            EXPECT_EQ(pair.client_owner.resets.front().second, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR));
        }
    }
    Pair              pair;
    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/r")};
    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();
    pair.client.read_stream(0, h3_headers_frame(0, {{":status", "200"}, {"content-length", "5"}}), false);
    pair.client.read_stream(0, h3_data_frame("abc"), false);
    pair.client.read_stream(0, h3_headers_frame(0, {{"x-sum", "1"}}), true);
    EXPECT_TRUE(pair.client_owner.responses.empty()) << "a trailer section ends a body its content-length contradicts";
    ASSERT_EQ(pair.client_owner.resets.size(), 1u);
    EXPECT_EQ(pair.client_owner.resets.front().second, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR));
    if (pair.client_owner.close) {
        EXPECT_EQ(pair.client_owner.close->first, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR)) << "nghttp3's own verdict";
    }
}

// A trailer section ends the message: a `content-length` the body it ends contradicts makes the request malformed beside
// every limit of the trailer section -- refused, never answered 431 (Huly QB-1197: the length was judged at the end of
// the stream, after the 431). nghttp3 then closes the connection for the mismatch.
TEST(Http3ConnectionDirect, AContentLengthATrailerSectionContradictsIsJudgedBeforeItsLimits) {
    using Fields = std::vector<std::pair<std::string, std::string>>;
    for (auto const &[tight, trailers] : std::vector<std::pair<TightLimits, Fields>>{
             {{.value = 4}, {{"x-v", "12345"}}},
             {{.name = 15}, {{"x-abcdefghijklmn", "1"}}}, // content-length's own name is within it
             {{.count = 2}, {{"x-a", "1"}, {"x-b", "2"}, {"x-c", "3"}}},
         }) {
        SCOPED_TRACE(trailers.back().first);
        LimitedPair pair{tight.limits()};
        auto        fields = request_fields("/upload");
        fields[0].second   = "POST";
        fields.emplace_back("content-length", "5");
        pair.server.read_stream(0, h3_headers_frame(0, fields), false);
        pair.server.read_stream(0, h3_data_frame("abc"), false);
        pair.server.read_stream(0, h3_headers_frame(0, trailers), true);
        expect_refused_unanswered(pair);
        if (pair.server_owner.close) {
            EXPECT_EQ(pair.server_owner.close->first, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR)) << "nghttp3's own verdict";
        }
    }
    // The control: a trailer section over the count after the body its content-length declares is answered 431.
    LimitedPair pair{TightLimits{.count = 2}.limits()};
    auto        fields = request_fields("/upload");
    fields[0].second   = "POST";
    fields.emplace_back("content-length", "3");
    pair.server.read_stream(0, h3_headers_frame(0, fields), false);
    pair.server.read_stream(0, h3_data_frame("abc"), false);
    pair.server.read_stream(0, h3_headers_frame(0, {{"x-a", "1"}, {"x-b", "2"}, {"x-c", "3"}}), true);
    EXPECT_TRUE(pair.server_owner.requests.empty());
    EXPECT_TRUE(stopped_without_error(pair.server_owner, 0)) << "answered 431";
    EXPECT_FALSE(reset(pair.server_owner, 0));
    EXPECT_FALSE(pair.server_owner.close.has_value());
}

// A field over the limits is judged before it is dropped (Huly QB-1197): in a trailer section, a field a trailer section
// must not carry (detail::is_forbidden_h3_trailer: `host`, `te`, the proxy authentication fields, `trailer`,
// `http2-settings`) -- over the value or the name limit, or past the count -- refuses the stream as it does within the
// limits; it was dropped unread and the request answered 431. A header section may carry the proxy authentication
// fields: over the limits there, the request is answered 431 (they were refused, as connection-specific fields).
// (nghttp3 refuses the connection-specific fields first, and removes a trailer section's `content-length` before this
// module sees it.)
TEST(Http3ConnectionDirect, AForbiddenFieldBesideTheLimitsRefusesTheStream) {
    using Fields    = std::vector<std::pair<std::string, std::string>>;
    auto shapes_for = [](std::string const &name, std::string const &value) {
        return std::vector<std::pair<TightLimits, Fields>>{
            {{.value = 4}, {{name, value}}},
            {{.name = 1}, {{name, value}}},
            {{.count = 2}, {{"x-a", "1"}, {"x-b", "2"}, {name, value}}},
        };
    };
    for (std::string const name : {"proxy-authorization", "proxy-authenticate"}) {
        for (auto const &[tight, extra] : shapes_for(name, "Basic x")) {
            SCOPED_TRACE("header section: " + name + ", " + std::to_string(extra.size()) + " fields");
            LimitedPair pair{tight.limits()};
            auto        fields = request_fields();
            fields.insert(fields.end(), extra.begin(), extra.end());
            pair.server.read_stream(0, h3_headers_frame(0, fields), true);
            EXPECT_TRUE(pair.server_owner.requests.empty());
            EXPECT_TRUE(stopped_without_error(pair.server_owner, 0)) << "answered 431";
            EXPECT_FALSE(reset(pair.server_owner, 0));
            EXPECT_FALSE(pair.server_owner.close.has_value()) << "the connection survives";
        }
    }
    // Fields a header section may carry, over the limits there: answered 431 -- the trailer list is a trailer section's.
    for (auto const &[name, value] :
         std::vector<std::pair<std::string, std::string>>{{"te", "trailers"}, {"trailer", "x-sum"}, {"http2-settings", "xx"}}) {
        SCOPED_TRACE("header section, well-formed: " + name);
        LimitedPair pair{TightLimits{.value = 1}.limits()};
        auto        fields = request_fields();
        fields.emplace_back(name, value); // over a value limit of 1
        pair.server.read_stream(0, h3_headers_frame(0, fields), true);
        EXPECT_TRUE(pair.server_owner.requests.empty());
        EXPECT_TRUE(stopped_without_error(pair.server_owner, 0)) << "answered 431";
        EXPECT_FALSE(reset(pair.server_owner, 0));
        EXPECT_FALSE(pair.server_owner.close.has_value());
    }
    for (std::string const name : {"host", "te", "proxy-authorization", "proxy-authenticate", "trailer", "http2-settings"}) {
        // `te` is `trailers` or nghttp3 refuses it first; a value of 8 bytes passes a value limit of 4.
        for (auto const &[tight, trailers] : shapes_for(name, "trailers")) {
            SCOPED_TRACE("trailer section: " + name + ", " + std::to_string(trailers.size()) + " fields");
            LimitedPair pair{tight.limits()};
            auto        fields = request_fields("/upload");
            fields[0].second   = "POST";
            pair.server.read_stream(0, h3_headers_frame(0, fields), false);
            pair.server.read_stream(0, h3_data_frame("abc"), false);
            pair.server.read_stream(0, h3_headers_frame(0, trailers), true);
            expect_refused_unanswered(pair);
            EXPECT_FALSE(pair.server_owner.close.has_value()) << "the connection survives";
        }
    }
}

namespace {

/// The size RFC 9114 section 4.2.2 counts for @p fields: every name and value, and 32 bytes a field.
std::uint64_t
field_section_size(std::vector<std::pair<std::string, std::string>> const &fields) {
    std::uint64_t size = 0;
    for (auto const &[name, value] : fields)
        size += name.size() + value.size() + 32;
    return size;
}

/// request_fields() and ten 6000-byte fields, then one more that brings the section to @p size exactly -- each field
/// within the default limits, the whole past nghttp3's reach: it does not enforce the 64 KiB it advertises.
std::vector<std::pair<std::string, std::string>>
section_of(std::uint64_t size, std::vector<std::pair<std::string, std::string>> fields = request_fields()) {
    for (int i = 0; i < 10; ++i)
        fields.emplace_back("x-" + std::to_string(i), std::string(6000, 'v'));
    const auto filler = size - field_section_size(fields) - std::string("x-z").size() - 32;
    fields.emplace_back("x-z", std::string(filler, 'v'));
    EXPECT_EQ(field_section_size(fields), size);
    return fields;
}

/// The request read raw on @p stream_id was answered -- its shape allows no answer but 431 -- then its read side
/// stopped without an error, the connection kept.
void
expect_answered_raw(LimitedPair const &pair, std::uint64_t stream_id) {
    // The answer's :status is no QPACK static-table entry, and its Huffman code is no shorter: it leaves as the text.
    bool status_431 = false;
    for (auto const &f : pair.server_owner.outbound)
        status_431 = status_431 || (f.stream_id == stream_id && f.data.find("431") != std::string::npos);
    EXPECT_TRUE(status_431) << "answered 431";
    EXPECT_TRUE(pair.server_owner.requests.empty()) << "a refused request is never delivered";
    EXPECT_TRUE(stopped_without_error(pair.server_owner, stream_id)) << "answered, then asked to stop sending without an error";
    EXPECT_FALSE(reset(pair.server_owner, stream_id)) << "answered, not refused";
    EXPECT_FALSE(pair.server_owner.close.has_value());
}

} // namespace

// A field section is bounded by the 64 KiB the connection advertises as SETTINGS_MAX_FIELD_SECTION_SIZE, counted as RFC
// 9114 section 4.2.2 counts it (Huly QB-1196): nghttp3 (1.18.0) does not enforce it, and sections of 72 KiB to 800 KiB,
// every field within the request limits, were delivered. Exactly 64 KiB is served; a byte more is a section over the
// limits -- answered 431 once the request is known well-formed, the fields past it dropped -- the header section as a
// trailer section, a pseudo-header's bytes counted too.
TEST(Http3ConnectionDirect, AFieldSectionPastTheAdvertisedSizeIsAnswered431) {
    constexpr std::uint64_t advertised = 64 * 1024;
    {
        Pair pair;
        pair.server.read_stream(0, h3_headers_frame(0, section_of(advertised)), true);
        ASSERT_EQ(pair.server_owner.requests.size(), 1u) << "a section of exactly 64 KiB is served";
        EXPECT_EQ(pair.server_owner.requests.front().header("x-z").size(), advertised - field_section_size(request_fields()) - 10 * 6035 - 35);
    }
    {
        // Sent by the client, which writes the same four pseudo-headers: the 431 is decoded.
        LimitedPair       pair{qb::http::request_limits{}};
        qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/")};
        for (auto const &[name, value] : section_of(advertised + 1))
            if (name.front() != ':')
                request.add_header(name, value);
        pair.exchange(0, request);
        EXPECT_TRUE(pair.server_owner.requests.empty()) << "a section of 64 KiB and a byte is refused";
        expect_answered(pair, 0, qb::http::status::REQUEST_HEADER_FIELDS_TOO_LARGE);
    }
    {
        // A :path that alone passes the section, with no target limit: the pseudo-headers are read all the same, 431.
        qb::http::request_limits limits;
        limits.max_url_length = 0;
        LimitedPair pair{limits};
        auto        fields = request_fields("/" + std::string(65400, 'a'));
        ASSERT_GT(field_section_size(fields), advertised);
        pair.server.read_stream(0, h3_headers_frame(0, fields), true);
        expect_answered_raw(pair, 0);
    }
    {
        // A trailer section is bounded alike, its size its own.
        LimitedPair pair{qb::http::request_limits{}};
        auto        fields = request_fields("/upload");
        fields[0].second   = "POST";
        pair.server.read_stream(0, h3_headers_frame(0, fields), false);
        pair.server.read_stream(0, h3_data_frame("abc"), false);
        pair.server.read_stream(0, h3_headers_frame(0, section_of(advertised + 1, {})), true);
        expect_answered_raw(pair, 0);

        pair.server.read_stream(4, h3_headers_frame(4, fields), false);
        pair.server.read_stream(4, h3_data_frame("abc"), false);
        pair.server.read_stream(4, h3_headers_frame(4, section_of(advertised, {})), true);
        ASSERT_EQ(pair.server_owner.requests.size(), 1u) << "a trailer section of exactly 64 KiB is read";
    }
}

// The section bound is a limit like the others (Huly QB-1196): a malformed request past it stays malformed, its stream
// refused, never answered 431 -- a `host` naming another authority than :authority, a `content-length` an ended stream
// contradicts -- and a well-formed `host` past it that stands for :authority is a field over the limits like any
// other, answered 431. The validation-beside-the-limits class of Huly QB-1195.
TEST(Http3ConnectionDirect, AMalformedRequestPastTheSectionSizeIsRefused) {
    constexpr std::uint64_t advertised = 64 * 1024;
    using Fields                       = std::vector<std::pair<std::string, std::string>>;
    const auto past                    = [&](Fields after, Fields lead = request_fields()) {
        auto fields = section_of(advertised, std::move(lead));
        fields.insert(fields.end(), after.begin(), after.end());
        return fields;
    };
    const Fields no_authority{{":method", "GET"}, {":scheme", "https"}, {":path", "/"}};
    for (auto const &[label, fields] : std::vector<std::pair<std::string, Fields>>{
             {"host naming another authority past it", past({{"host", "evil.test"}})},
             {"host that is no authority, past it, without :authority", past({{"host", "example.test:99999"}}, no_authority)},
             {"content-length past it, the stream ended", past({{"content-length", "5"}})},
         }) {
        SCOPED_TRACE(label);
        LimitedPair pair{qb::http::request_limits{}};
        pair.server.read_stream(0, h3_headers_frame(0, fields), true);
        expect_refused_unanswered(pair);
    }
    // Well-formed past it, answered: a host that stands for :authority, a content-length the ended stream does not
    // contradict -- both kept to be judged --, and `proxy-authorization`, which a header section may carry (it was
    // refused as a connection-specific field, Huly QB-1197).
    for (auto const &fields :
         {past({{"host", "example.test"}}, no_authority), past({{"content-length", "0"}}), past({{"proxy-authorization", "Basic x"}})}) {
        LimitedPair pair{qb::http::request_limits{}};
        pair.server.read_stream(0, h3_headers_frame(0, fields), true);
        expect_answered_raw(pair, 0);
    }
    // A trailer section past it carrying a field a trailer section must not: refused, never answered.
    {
        LimitedPair pair{qb::http::request_limits{}};
        auto        fields = request_fields("/upload");
        fields[0].second   = "POST";
        pair.server.read_stream(0, h3_headers_frame(0, fields), false);
        pair.server.read_stream(0, h3_data_frame("abc"), false);
        auto trailers = section_of(advertised, {});
        trailers.emplace_back("host", "example.test");
        pair.server.read_stream(0, h3_headers_frame(0, trailers), true);
        expect_refused_unanswered(pair);
        EXPECT_FALSE(pair.server_owner.close.has_value());
    }
    // A trailer section past it, ending a body its content-length contradicts: refused, never answered 431.
    {
        LimitedPair pair{qb::http::request_limits{}};
        auto        fields = request_fields("/upload");
        fields[0].second   = "POST";
        fields.emplace_back("content-length", "5");
        pair.server.read_stream(0, h3_headers_frame(0, fields), false);
        pair.server.read_stream(0, h3_data_frame("abc"), false);
        pair.server.read_stream(0, h3_headers_frame(0, section_of(advertised + 1, {})), true);
        expect_refused_unanswered(pair);
    }
}

// The client reads a response under the same bound: a section past the 64 KiB it advertises refuses the stream, as a
// response over the limits does; one of exactly 64 KiB is delivered (Huly QB-1196: any size was), a trailer section
// alike. An informational response's section is a section of its own and its fields go with it: three 103s of 40 KB,
// then a 200 of 40 KB, deliver the 200's fields alone -- they were added to the final response's, unbounded.
TEST(Http3ConnectionDirect, AResponseSectionPastTheAdvertisedSizeRefusesTheStream) {
    constexpr std::uint64_t advertised = 64 * 1024;
    for (const std::uint64_t size : {advertised, advertised + 1}) {
        Pair              pair;
        qb::http::Request get{qb::http::method::GET, qb::io::uri("https://example.test/r")};
        ASSERT_TRUE(pair.client.submit_request(0, get));
        pair.settle();
        pair.client.read_stream(0, h3_headers_frame(0, section_of(size, {{":status", "200"}})), true);
        if (size == advertised) {
            ASSERT_EQ(pair.client_owner.responses.size(), 1u) << "a section of exactly 64 KiB is delivered";
            EXPECT_TRUE(pair.client_owner.resets.empty());
        } else {
            EXPECT_TRUE(pair.client_owner.responses.empty()) << "a section of 64 KiB and a byte is refused";
            ASSERT_EQ(pair.client_owner.resets.size(), 1u);
            EXPECT_EQ(pair.client_owner.resets.front().second, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR));
        }
        EXPECT_FALSE(pair.client_owner.close.has_value());
    }
    Pair              pair;
    qb::http::Request get{qb::http::method::GET, qb::io::uri("https://example.test/r")};
    ASSERT_TRUE(pair.client.submit_request(0, get));
    pair.settle();
    auto section = [](std::string status) {
        std::vector<std::pair<std::string, std::string>> fields{{":status", std::move(status)}};
        for (int i = 0; i < 8; ++i)
            fields.emplace_back("x-" + std::to_string(i), std::string(5000, 'v'));
        return fields;
    };
    for (int i = 0; i < 3; ++i) {
        auto early = section("103");
        early.emplace_back("link", "</a.css>; rel=preload");
        pair.client.read_stream(0, h3_headers_frame(0, early), false);
    }
    pair.client.read_stream(0, h3_headers_frame(0, section("200")), true);
    ASSERT_EQ(pair.client_owner.responses.size(), 1u) << "each section is counted on its own";
    auto const &response = pair.client_owner.responses.front();
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_FALSE(response.has_header("link")) << "an informational response's field read as the final one's";
    ASSERT_TRUE(response.has_header("x-0"));
    EXPECT_EQ(response.headers().find("x-0")->second.size(), 1u) << "the final section's fields alone";
    EXPECT_TRUE(pair.client_owner.resets.empty());

    // A response's trailer section past the bound refuses the stream too.
    Pair trailed;
    ASSERT_TRUE(trailed.client.submit_request(0, get));
    trailed.settle();
    trailed.client.read_stream(0, h3_headers_frame(0, {{":status", "200"}}), false);
    trailed.client.read_stream(0, h3_data_frame("abc"), false);
    trailed.client.read_stream(0, h3_headers_frame(0, section_of(advertised + 1, {})), true);
    EXPECT_TRUE(trailed.client_owner.responses.empty());
    ASSERT_EQ(trailed.client_owner.resets.size(), 1u);
    EXPECT_EQ(trailed.client_owner.resets.front().second, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR));

    // An informational response alone ends no response: one that ends the stream, one the stream's end follows, one a
    // header section without :status follows -- nothing is delivered. nghttp3 (1.18.0) closes the connection for each
    // first, so this pins its tier: this module's own guards (end_stream_cb, materialize_trailers) are defensive.
    for (int shape = 0; shape < 3; ++shape) {
        SCOPED_TRACE(shape);
        Pair alone;
        ASSERT_TRUE(alone.client.submit_request(0, get));
        alone.settle();
        alone.client.read_stream(0, h3_headers_frame(0, {{":status", "103"}, {"link", "</a.css>"}}), shape == 0);
        if (shape == 1)
            alone.client.read_stream(0, "", true);
        if (shape == 2)
            alone.client.read_stream(0, h3_headers_frame(0, {{"x-t", "1"}}), true);
        EXPECT_TRUE(alone.client_owner.responses.empty()) << "no response came";
        EXPECT_TRUE(alone.client_owner.close.has_value() || !alone.client_owner.resets.empty());
    }

    // An interim section past the bound refuses the stream as a final one does; a final response that ends the stream
    // after a 1xx is judged by its own content-length, which the 1xx's reset left for it.
    {
        Pair big;
        ASSERT_TRUE(big.client.submit_request(0, get));
        big.settle();
        big.client.read_stream(0, h3_headers_frame(0, section_of(advertised + 1, {{":status", "103"}})), false);
        EXPECT_TRUE(big.client_owner.responses.empty());
        ASSERT_EQ(big.client_owner.resets.size(), 1u);
        EXPECT_EQ(big.client_owner.resets.front().second, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR));
    }
    {
        Pair after;
        ASSERT_TRUE(after.client.submit_request(0, get));
        after.settle();
        after.client.read_stream(0, h3_headers_frame(0, {{":status", "103"}, {"link", "</a.css>"}}), false);
        after.client.read_stream(0, h3_headers_frame(0, {{":status", "200"}, {"content-length", "5"}}), true);
        EXPECT_TRUE(after.client_owner.responses.empty());
        ASSERT_EQ(after.client_owner.resets.size(), 1u);
        EXPECT_EQ(after.client_owner.resets.front().second, static_cast<std::uint64_t>(NGHTTP3_H3_MESSAGE_ERROR));
    }
}

#endif // QBM_HTTP_HAS_HTTP3

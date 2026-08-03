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
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <qb/system/container/unordered_map.h>

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

// Pump bytes back and forth until neither side has anything left to deliver (bounded so a logic bug
// can never spin forever). Templated so a derived owner/connection (e.g. a body-capped server) pumps too.
template <typename ClientOwnerT, typename ClientConnT, typename ServerOwnerT, typename ServerConnT>
void
pump(ClientOwnerT &client_owner, ClientConnT &client_conn, ServerOwnerT &server_owner, ServerConnT &server_conn) {
    for (int i = 0; i < 64; ++i) {
        const auto a = deliver(client_owner, server_conn);
        const auto b = deliver(server_owner, client_conn);
        if (a == 0 && b == 0)
            return;
    }
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
    EXPECT_EQ(got.header("x-checksum"), "deadbeef") << "the announced trailer must reach the server as a header";
    EXPECT_FALSE(pair.server_owner.close.has_value());
}

// =============================================================================
// SUBMIT-TIME REJECTIONS (validation arms in submit_request / submit_response)
// =============================================================================

/**
 * @test submit_request rejects a content-length that disagrees with the body
 * @brief make_request_headers fails when the declared content-length != body size, so submit_request
 *        returns false before anything is sent — the server never sees a request.
 */
TEST(Http3ConnectionDirect, SubmitRequestRejectsContentLengthBodyMismatch) {
    Pair pair;

    qb::http::Request request{qb::http::method::POST, qb::io::uri("https://example.test/x")};
    request.body() = "12345";
    request.set_header("content-length", "99");

    EXPECT_FALSE(pair.client.submit_request(0, request));
    pair.settle();
    EXPECT_TRUE(pair.server_owner.requests.empty());
}

/**
 * @test submit_request rejects a forbidden hop-by-hop header
 * @brief A `connection` header is forbidden in HTTP/3 (RFC 9114 4.2); make_request_headers returns
 *        nullopt so submit_request returns false and emits nothing.
 */
TEST(Http3ConnectionDirect, SubmitRequestRejectsForbiddenHeader) {
    Pair pair;

    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/x")};
    request.set_header("connection", "keep-alive");

    EXPECT_FALSE(pair.client.submit_request(0, request));
    pair.settle();
    EXPECT_TRUE(pair.server_owner.requests.empty());
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
 * @test submit_response rejects a declared trailer with no valid trailer block
 * @brief A response that announces `trailer` but whose announced field resolves to nothing valid
 *        (here a forbidden `content-length` trailer name) makes make_trailers return nullopt while a
 *        trailer header is present, so submit_response returns false.
 */
TEST(Http3ConnectionDirect, SubmitResponseRejectsAnnouncedButInvalidTrailer) {
    Pair pair;

    qb::http::Request request{qb::http::method::GET, qb::io::uri("https://example.test/x")};
    ASSERT_TRUE(pair.client.submit_request(0, request));
    pair.settle();

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("trailer", "content-length"); // content-length is a forbidden trailer name
    response.set_header("content-length", "0");

    EXPECT_FALSE(pair.server.submit_response(0, response));
}

// =============================================================================
// INBOUND BODY CAP — recv_data_cb resets a stream whose body exceeds the limit
// =============================================================================

/**
 * @test A request body exceeding the owner's cap is reset in recv_data_cb and never delivered
 * @brief When the Owner exposes max_http3_body_size() (detected via `requires`), recv_data_cb tracks the
 *        accumulating body and, once it would exceed the limit, calls reset_http3_stream with
 *        NGHTTP3_H3_REQUEST_CANCELLED and fails the callback. The over-limit request is therefore reset
 *        (the owner records the reset) and never materialized into on_http3_request. This is the body-cap
 *        arm of recv_data_cb, only compiled in when the owner advertises a cap.
 */
TEST(Http3ConnectionDirect, ServerResetsRequestWhoseBodyExceedsCap) {
    // A server owner that advertises a tight body cap, so the recv_data_cb `requires` arm is compiled in.
    struct CappedServerOwner : ServerOwner {
        std::uint64_t
        max_http3_body_size() const noexcept {
            return 16; // bytes
        }
    };
    using CappedServerConnection = connection<CappedServerOwner>;

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
    pump(client_owner, client, server_owner, server);

    EXPECT_TRUE(server_owner.requests.empty()) << "an over-cap request must not be delivered";
    const bool reset_request_stream =
        std::any_of(server_owner.resets.begin(), server_owner.resets.end(), [](auto const &r) { return r.first == 0u; });
    EXPECT_TRUE(reset_request_stream) << "recv_data_cb must reset the over-cap request stream";
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

#endif // QBM_HTTP_HAS_HTTP3

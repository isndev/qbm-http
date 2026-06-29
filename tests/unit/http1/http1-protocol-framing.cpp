/**
 * @file qbm/http/tests/unit/http1/http1-protocol-framing.cpp
 * @brief Socket-less drive of the HTTP/1.x protocol message-framing state machine.
 *
 * The pure-`Parser<>` paths are covered by http1-parse-limits.cpp; this file
 * targets the layer above it — `qb::protocol::http::base<IO_Handler, Trait>`
 * (1.1/protocol/base.h) and its concrete `server` / `client` specializations
 * (1.1/protocol/server.h, 1.1/protocol/client.h). That `getMessageSize()` /
 * `onMessage()` state machine is what a real connection runs but no unit test
 * exercised: it is driven here without a socket or event loop via a tiny
 * "FakeIO" handler that owns an input/output `qb::allocator::pipe<char>` and the
 * `on(Request&&)` / `on(Response&&)` sinks the protocol dispatches to (the same
 * harness shape used by the HTTP/2 tests in shared/http2_fake_io.h).
 *
 * Wire behavior asserted against base.h:
 *   - Content-Length framing: getMessageSize() returns 0 until the whole
 *     (headers + declared body) is buffered, then returns the exact full size;
 *     the parsed body view equals the on-wire bytes; the request/response is
 *     dispatched exactly once by onMessage(); zero-length bodies frame on the
 *     header terminator alone.
 *   - Chunked Transfer-Encoding framing: the resume()+parse() body loop returns
 *     0 while chunks are still arriving and the precise message size once the
 *     0-CRLF terminator (optionally with trailers) lands; single chunk, multiple
 *     chunks and chunk-extension/trailer variants all reassemble the dechunked
 *     body.
 *   - Partial / streamed feeds: headers split mid-line, and a body split across
 *     reads, both frame correctly once the tail arrives (the header-incomplete
 *     branch resets the parser and re-feeds the whole buffer; the body branch
 *     keeps accumulating).
 *   - Pipelining: two complete messages back-to-back in one buffer are framed
 *     and dispatched one at a time as the consumed prefix is freed.
 *   - Malformed input: a bad request line / bad chunk size marks the protocol
 *     not_ok() (no message, ok()==false) instead of silently stalling.
 *   - Response specifics: status capture, no-body statuses (204/304) ignore a
 *     declared Content-Length, and the HEAD `http1_response_body_forbidden()`
 *     hook frames a body-bearing response on its headers alone.
 *   - keep-alive / Connection close derivation surfaces on the dispatched msg.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <cstring>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <qb/system/allocator/pipe.h>

#include "../1.1/protocol/client.h"
#include "../1.1/protocol/server.h"
#include "../http.h"

using namespace qb::http;

namespace {

// ===========================================================================
// Socket-less IO handlers satisfying the protocol's IO concept.
//
// base<IO_Handler, Trait> needs:
//   - using base_io_t = <self>;     (AProtocol<_IO_>'s friend typename _IO_::base_io_t)
//   - in()  -> qb::allocator::pipe<char>&   (the unconsumed input buffer)
//   - on(Request&&) / on(Response&&)        (server.h / client.h dispatch sink)
// The client (Response) IO additionally exposes http1_response_body_forbidden()
// so the HEAD no-body-response branch in getMessageSize() can be reached.
// ===========================================================================

struct ServerFakeIO {
    using base_io_t = ServerFakeIO;

    qb::allocator::pipe<char> input;

    int                              request_count = 0;
    std::optional<qb::http::Request> last_request;

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }

    void
    on(qb::http::Request &&request) {
        ++request_count;
        last_request = std::move(request);
    }
};

struct ClientFakeIO {
    using base_io_t = ClientFakeIO;

    qb::allocator::pipe<char> input;

    int                               response_count = 0;
    bool                              body_forbidden = false;
    std::optional<qb::http::Response> last_response;

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }

    // Reached by the response-body-forbidden (HEAD) branch in getMessageSize().
    [[nodiscard]] bool
    http1_response_body_forbidden() const noexcept {
        return body_forbidden;
    }

    void
    on(qb::http::Response &&response) {
        ++response_count;
        last_response = std::move(response);
    }
};

// --- raw-byte buffer helpers ----------------------------------------------

template <typename FakeIO>
void
feed(FakeIO &io, std::string_view bytes) {
    if (!bytes.empty()) {
        std::memcpy(io.input.allocate_back(bytes.size()), bytes.data(), bytes.size());
    }
}

// Drive one framing step: getMessageSize() -> (onMessage + free) when a whole
// message is available. Returns the size reported (0 if incomplete / error).
template <typename Protocol, typename FakeIO>
std::size_t
step(Protocol &protocol, FakeIO &io) {
    const std::size_t sz = protocol.getMessageSize();
    if (sz > 0) {
        protocol.onMessage(sz);
        io.input.free_front(sz);
    }
    return sz;
}

// ===========================================================================
// Server-side (Request) framing
// ===========================================================================

TEST(Http1ProtocolFraming, ContentLengthRequestFramesAndDispatchesExactlyOnce) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);

    feed(io, "POST /submit HTTP/1.1\r\n"
             "Host: example.test\r\n"
             "Content-Length: 11\r\n\r\n"
             "hello world");

    const std::size_t sz = step(proto, io);
    EXPECT_GT(sz, 0u);
    EXPECT_TRUE(proto.ok());
    EXPECT_EQ(io.request_count, 1);
    EXPECT_EQ(io.input.size(), 0u); // whole message consumed

    ASSERT_TRUE(io.last_request.has_value());
    auto &req = *io.last_request;
    EXPECT_EQ(req.method(), HTTP_POST);
    EXPECT_EQ(req.uri().path(), "/submit");
    EXPECT_EQ(req.header("Host"), "example.test");
    EXPECT_EQ(req.major_version, 1u);
    EXPECT_EQ(req.minor_version, 1u);
    EXPECT_EQ(req.body().size(), 11u);
    EXPECT_EQ(req.body().as<std::string>(), "hello world");
}

TEST(Http1ProtocolFraming, HeaderOnlyGetFramesWithEmptyBody) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);

    feed(io, "GET /health HTTP/1.1\r\nHost: h\r\n\r\n");

    EXPECT_GT(step(proto, io), 0u);
    EXPECT_EQ(io.request_count, 1);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_EQ(io.last_request->method(), HTTP_GET);
    EXPECT_EQ(io.last_request->body().size(), 0u);
    EXPECT_TRUE(io.last_request->keep_alive); // HTTP/1.1 default
}

TEST(Http1ProtocolFraming, IncompleteBodyReturnsZeroUntilFullyBuffered) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);

    // Headers + only part of the declared 10-byte body present.
    feed(io, "POST /x HTTP/1.1\r\nContent-Length: 10\r\n\r\nABCDE");
    EXPECT_EQ(step(proto, io), 0u); // body incomplete -> 0, no dispatch
    EXPECT_EQ(io.request_count, 0);
    EXPECT_TRUE(proto.ok());

    // Remaining body arrives.
    feed(io, "FGHIJ");
    EXPECT_GT(step(proto, io), 0u);
    EXPECT_EQ(io.request_count, 1);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_EQ(io.last_request->body().as<std::string>(), "ABCDEFGHIJ");
}

TEST(Http1ProtocolFraming, HeadersSplitMidLineReassembleAndFrame) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);

    // First read ends mid header-block: parser cannot complete headers, returns 0.
    feed(io, "GET /partial HTTP/1.1\r\nX-Cus");
    EXPECT_EQ(step(proto, io), 0u);
    EXPECT_EQ(io.request_count, 0);
    EXPECT_TRUE(proto.ok());

    // Rest of the header block + terminator.
    feed(io, "tom: value\r\nContent-Length: 3\r\n\r\nabc");
    EXPECT_GT(step(proto, io), 0u);
    EXPECT_EQ(io.request_count, 1);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_EQ(io.last_request->header("X-Custom"), "value");
    EXPECT_EQ(io.last_request->body().as<std::string>(), "abc");
}

TEST(Http1ProtocolFraming, PipelinedRequestsAreFramedOneAtATime) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);

    feed(io, "GET /first HTTP/1.1\r\nHost: h\r\n\r\n"
             "GET /second HTTP/1.1\r\nHost: h\r\n\r\n");

    EXPECT_GT(step(proto, io), 0u);
    ASSERT_EQ(io.request_count, 1);
    EXPECT_EQ(io.last_request->uri().path(), "/first");
    EXPECT_GT(io.input.size(), 0u); // second request still buffered

    EXPECT_GT(step(proto, io), 0u);
    ASSERT_EQ(io.request_count, 2);
    EXPECT_EQ(io.last_request->uri().path(), "/second");
    EXPECT_EQ(io.input.size(), 0u);
}

TEST(Http1ProtocolFraming, ConnectionCloseDerivesKeepAliveFalse) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);

    feed(io, "GET / HTTP/1.1\r\nConnection: close\r\n\r\n");
    EXPECT_GT(step(proto, io), 0u);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_FALSE(io.last_request->keep_alive);
}

TEST(Http1ProtocolFraming, MalformedRequestLineMarksProtocolNotOk) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);

    // "SP/2.5" is not a valid HTTP version token -> llhttp errors at the request line.
    feed(io, "GET / SP/2.5\r\nHost: h\r\n\r\n");
    EXPECT_EQ(proto.getMessageSize(), 0u);
    EXPECT_FALSE(proto.ok());
    EXPECT_EQ(io.request_count, 0);
}

// ===========================================================================
// Chunked Transfer-Encoding framing (the resume()+parse() body loop)
// ===========================================================================

TEST(Http1ProtocolFraming, SingleChunkBodyFramesAndDechunks) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);

    feed(io, "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
             "5\r\nhello\r\n0\r\n\r\n");

    EXPECT_GT(step(proto, io), 0u);
    EXPECT_EQ(io.request_count, 1);
    EXPECT_EQ(io.input.size(), 0u);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_EQ(io.last_request->body().as<std::string>(), "hello");
}

TEST(Http1ProtocolFraming, MultipleChunksReassembleInOrder) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);

    feed(io, "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
             "3\r\nabc\r\n"
             "3\r\ndef\r\n"
             "1\r\ng\r\n"
             "0\r\n\r\n");

    EXPECT_GT(step(proto, io), 0u);
    EXPECT_EQ(io.request_count, 1);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_EQ(io.last_request->body().as<std::string>(), "abcdefg");
}

TEST(Http1ProtocolFraming, ChunkedBodyIncompleteUntilZeroTerminatorArrives) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);

    // Headers + one chunk, but no terminating 0-chunk yet.
    feed(io, "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n");
    EXPECT_EQ(step(proto, io), 0u); // body loop returns 0 -> still accumulating
    EXPECT_EQ(io.request_count, 0);
    EXPECT_TRUE(proto.ok());

    // Another chunk, still no terminator.
    feed(io, "2\r\nde\r\n");
    EXPECT_EQ(step(proto, io), 0u);
    EXPECT_EQ(io.request_count, 0);

    // Final 0-chunk terminator.
    feed(io, "0\r\n\r\n");
    EXPECT_GT(step(proto, io), 0u);
    EXPECT_EQ(io.request_count, 1);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_EQ(io.last_request->body().as<std::string>(), "abcde");
}

TEST(Http1ProtocolFraming, ChunkExtensionsAndTrailersAreAcceptedAndStripped) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);

    // Chunk-size line carries an extension (";a=b"); a trailer header follows the
    // 0-chunk. Both must be tolerated and excluded from the dechunked body.
    feed(io, "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
             "4;a=b\r\nbody\r\n"
             "0\r\n"
             "X-Trailer: t\r\n\r\n");

    EXPECT_GT(step(proto, io), 0u);
    EXPECT_EQ(io.request_count, 1);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_EQ(io.last_request->body().as<std::string>(), "body");
}

TEST(Http1ProtocolFraming, BadChunkSizeMarksProtocolNotOk) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);

    // "zz" is not a valid hex chunk size.
    feed(io, "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n");
    EXPECT_EQ(step(proto, io), 0u);
    EXPECT_FALSE(proto.ok());
    EXPECT_EQ(io.request_count, 0);
}

// ===========================================================================
// Client-side (Response) framing
// ===========================================================================

TEST(Http1ProtocolFraming, ResponseContentLengthFramesAndCapturesStatusAndBody) {
    ClientFakeIO                             io;
    qb::protocol::http::client<ClientFakeIO> proto(io);

    feed(io, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nworld");

    EXPECT_GT(step(proto, io), 0u);
    EXPECT_EQ(io.response_count, 1);
    EXPECT_EQ(io.input.size(), 0u);
    ASSERT_TRUE(io.last_response.has_value());
    auto &res = *io.last_response;
    EXPECT_EQ(res.status(), 200);
    EXPECT_EQ(res.body().as<std::string>(), "world");
    EXPECT_EQ(res.header("Content-Type"), "text/plain");
}

TEST(Http1ProtocolFraming, ResponseChunkedBodyFramesAndDechunks) {
    ClientFakeIO                             io;
    qb::protocol::http::client<ClientFakeIO> proto(io);

    feed(io, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
             "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n");

    EXPECT_GT(step(proto, io), 0u);
    EXPECT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_response.has_value());
    EXPECT_EQ(io.last_response->body().as<std::string>(), "Wikipedia");
}

TEST(Http1ProtocolFraming, NoContentResponseIgnoresDeclaredContentLength) {
    ClientFakeIO                             io;
    qb::protocol::http::client<ClientFakeIO> proto(io);

    // 204 must carry no body even though a (bogus) Content-Length is present.
    feed(io, "HTTP/1.1 204 No Content\r\nContent-Length: 4\r\n\r\n");

    EXPECT_GT(step(proto, io), 0u);
    EXPECT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_response.has_value());
    EXPECT_EQ(io.last_response->status(), 204);
    EXPECT_EQ(io.last_response->body().size(), 0u);
    EXPECT_EQ(io.input.size(), 0u); // framed on the header terminator alone
}

TEST(Http1ProtocolFraming, NotModifiedResponseIgnoresDeclaredContentLength) {
    ClientFakeIO                             io;
    qb::protocol::http::client<ClientFakeIO> proto(io);

    feed(io, "HTTP/1.1 304 Not Modified\r\nContent-Length: 7\r\n\r\n");

    EXPECT_GT(step(proto, io), 0u);
    EXPECT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_response.has_value());
    EXPECT_EQ(io.last_response->status(), 304);
    EXPECT_EQ(io.last_response->body().size(), 0u);
}

// The HEAD request path: the response to a HEAD declares a Content-Length but
// carries NO body on the wire. http1_response_body_forbidden() makes
// getMessageSize() frame on the headers alone and ignore the declared length.
TEST(Http1ProtocolFraming, HeadResponseBodyForbiddenFramesOnHeadersOnly) {
    ClientFakeIO io;
    io.body_forbidden = true;
    qb::protocol::http::client<ClientFakeIO> proto(io);

    feed(io, "HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n");

    const std::size_t sz = step(proto, io);
    EXPECT_GT(sz, 0u);
    EXPECT_EQ(io.response_count, 1);
    EXPECT_EQ(io.input.size(), 0u); // no 42-byte body was awaited
    ASSERT_TRUE(io.last_response.has_value());
    EXPECT_EQ(io.last_response->status(), 200);
    EXPECT_EQ(io.last_response->body().size(), 0u);
}

TEST(Http1ProtocolFraming, ResponseBodySplitAcrossReadsFrames) {
    ClientFakeIO                             io;
    qb::protocol::http::client<ClientFakeIO> proto(io);

    feed(io, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nfoo");
    EXPECT_EQ(step(proto, io), 0u); // half the body present
    EXPECT_EQ(io.response_count, 0);

    feed(io, "bar");
    EXPECT_GT(step(proto, io), 0u);
    EXPECT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_response.has_value());
    EXPECT_EQ(io.last_response->body().as<std::string>(), "foobar");
}

// ===========================================================================
// Serializer round-trip: build -> serialize -> parse through the protocol,
// asserting the parsed message matches the source (real wire fidelity).
// ===========================================================================

TEST(Http1ProtocolFraming, RequestSerializerRoundTripsThroughParser) {
    qb::http::Request request{qb::http::method::POST, {"http://example.test/api/items?id=7"}};
    request.set_header("Host", "example.test");
    request.set_header("Content-Type", "text/plain");
    request.body() = "payload-bytes";

    qb::allocator::pipe<char> wire;
    ASSERT_NO_THROW(wire << request);

    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);
    feed(io, std::string_view(wire.begin(), wire.size()));

    EXPECT_GT(step(proto, io), 0u);
    ASSERT_TRUE(io.last_request.has_value());
    auto &req = *io.last_request;
    EXPECT_EQ(req.method(), HTTP_POST);
    EXPECT_EQ(req.uri().path(), "/api/items");
    EXPECT_EQ(req.query("id"), "7");
    EXPECT_EQ(req.header("Content-Type"), "text/plain");
    EXPECT_EQ(req.body().as<std::string>(), "payload-bytes");
}

TEST(Http1ProtocolFraming, ResponseSerializerRoundTripsThroughParser) {
    qb::http::Response response;
    response.status() = qb::http::status::CREATED;
    response.set_header("Content-Type", "application/json");
    response.body() = R"({"ok":true})";

    qb::allocator::pipe<char> wire;
    ASSERT_NO_THROW(wire << response);

    ClientFakeIO                             io;
    qb::protocol::http::client<ClientFakeIO> proto(io);
    feed(io, std::string_view(wire.begin(), wire.size()));

    EXPECT_GT(step(proto, io), 0u);
    ASSERT_TRUE(io.last_response.has_value());
    auto &res = *io.last_response;
    EXPECT_EQ(res.status(), 201);
    EXPECT_EQ(res.header("Content-Type"), "application/json");
    EXPECT_EQ(res.body().as<std::string>(), R"({"ok":true})");
}

TEST(Http1ProtocolFraming, ChunkedSerializerRoundTripsThroughParser) {
    // The serializer emits chunked framing; the parser must dechunk back to the
    // original body bytes (end-to-end Transfer-Encoding fidelity).
    qb::http::Request request{qb::http::method::POST, {"http://example.test/stream"}};
    request.set_header("Host", "example.test");
    request.set_header("Transfer-Encoding", "chunked");
    request.body() = "streamed-content";

    qb::allocator::pipe<char> wire;
    ASSERT_NO_THROW(wire << request);
    // Sanity: the serialized form really is chunked, not Content-Length.
    const std::string wire_str(wire.begin(), wire.size());
    ASSERT_NE(wire_str.find("transfer-encoding: chunked\r\n"), std::string::npos);
    ASSERT_EQ(wire_str.find("content-length:"), std::string::npos);

    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);
    feed(io, wire_str);

    EXPECT_GT(step(proto, io), 0u);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_EQ(io.last_request->body().as<std::string>(), "streamed-content");
}

} // namespace

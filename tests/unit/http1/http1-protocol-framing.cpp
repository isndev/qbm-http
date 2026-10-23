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

#include <qbm/http/1.1/protocol/client.h>
#include <qbm/http/1.1/protocol/server.h>
#include <qbm/http/http.h>

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

TEST(Http1ProtocolFraming, InformationalResponsesAreSeparateBodylessMessagesAtEveryByteBoundary) {
    ClientFakeIO                                   io;
    qb::protocol::http::client<ClientFakeIO>       proto(io);
    const std::vector<std::pair<std::string, int>> messages = {
        {"HTTP/1.1 100 Continue\r\n\r\n", 100},
        {"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n", 103},
        {"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone", 200}
    };
    int received = 0;
    for (auto const &[wire, status] : messages) {
        for (std::size_t n = 0; n < wire.size(); ++n) {
            feed(io, std::string_view(wire).substr(n, 1));
            step(proto, io);
            ASSERT_TRUE(proto.ok());
            EXPECT_EQ(io.response_count, received + (n + 1 == wire.size() ? 1 : 0));
        }
        ++received;
        ASSERT_TRUE(io.last_response);
        EXPECT_EQ(io.last_response->status(), status);
        EXPECT_EQ(io.last_response->body().as<std::string>(), status == 200 ? "done" : "");
    }
    EXPECT_EQ(io.input.size(), 0u);
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

TEST(Http1ProtocolFraming, ResponseCloseDelimitedBodyAccumulatesAndFlushesOnEof) {
    ClientFakeIO                             io;
    qb::protocol::http::client<ClientFakeIO> proto(io);

    // No Content-Length, no Transfer-Encoding, body-bearing 200: the body is delimited by the
    // connection close (RFC 9112 §6.3). getMessageSize must NOT frame this as an empty body (the
    // old behaviour, which dropped the payload) — it returns 0 (keep buffering) and flush_eof()
    // delivers the accumulated body when the connection closes.
    feed(io, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHELLO-CLOSE-DELIMITED-BODY");

    EXPECT_EQ(step(proto, io), 0u); // buffered, not dispatched yet
    EXPECT_EQ(io.response_count, 0);

    proto.flush_eof(); // connection closed -> deliver the body
    EXPECT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_response.has_value());
    EXPECT_EQ(io.last_response->status(), 200);
    EXPECT_EQ(io.last_response->body().as<std::string>(), "HELLO-CLOSE-DELIMITED-BODY");

    // Idempotent: a second flush (teardown re-entry) must not re-dispatch.
    proto.flush_eof();
    EXPECT_EQ(io.response_count, 1);
}

TEST(Http1ProtocolFraming, ResponseCloseDelimitedBodyAccumulatesAcrossStreamedFeeds) {
    ClientFakeIO                             io;
    qb::protocol::http::client<ClientFakeIO> proto(io);

    feed(io, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n");
    EXPECT_EQ(step(proto, io), 0u); // headers complete, close-delimited -> accumulate
    feed(io, "part-one;");
    EXPECT_EQ(step(proto, io), 0u);
    feed(io, "part-two");
    EXPECT_EQ(step(proto, io), 0u);
    EXPECT_EQ(io.response_count, 0);

    proto.flush_eof();
    EXPECT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_response.has_value());
    EXPECT_EQ(io.last_response->body().as<std::string>(), "part-one;part-two");
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

// ===========================================================================
// Header-block parsing must be LINEAR in the header size, not quadratic.
//
// While the header block is incomplete, getMessageSize() used to reset() the parser and re-feed
// it the ENTIRE accumulated buffer on every arrival — so a header block delivered in N segments
// was parsed N times, over a growing prefix each time. The peer chooses the segmentation, and the
// header block can legally reach ~793 KB (99 headers at the configured name/value ceilings), so a
// single well-formed request delivered in 64-byte segments cost 1.5 SECONDS of parsing, ~95 s
// extrapolated to byte-at-a-time. A VirtualCore is single-threaded: that stalls every actor on the
// core. One legal request per connection is a remote CPU denial of service.
//
// The parser's callbacks were already fragmentation-safe (on_header_field / on_header_value append
// and commit a pair exactly once on the field<->value transition; on_url accumulates), so the reset
// was not needed — only its stale rationale comment said otherwise. getMessageSize() now feeds only
// the bytes that arrived since the previous call.
//
// The oracle is llhttp's own consumption, not wall-clock: `total_parsed` sums how many bytes the
// parser was handed across the whole delivery. Linear means it stays within a small constant of the
// header block size; the quadratic shape makes it O(size^2 / segment), which for these numbers is
// four orders of magnitude larger. That is deterministic and cannot flake on a loaded machine.
// ===========================================================================

namespace {

std::string
big_header_block(std::size_t headers, std::size_t value_len) {
    std::string raw = "GET /linear HTTP/1.1\r\nHost: x\r\n";
    for (std::size_t i = 0; i < headers; ++i)
        raw += "X-Pad-" + std::to_string(i) + ": " + std::string(value_len, 'v') + "\r\n";
    raw += "\r\n";
    return raw;
}

/// Exposes the protected parser so the test can observe PARTIAL header state between arrivals —
/// the deterministic signal that separates incremental parsing from reset-and-re-feed.
struct PeekableServer : qb::protocol::http::server<ServerFakeIO> {
    using qb::protocol::http::server<ServerFakeIO>::server;
    [[nodiscard]] const qb::http::Request &
    peek() const noexcept {
        return const_cast<PeekableServer *>(this)->_http_obj.get_parsed_message();
    }
};

} // namespace

TEST(Http1ProtocolFraming, LargeHeaderBlockInSmallSegmentsIsParsedOnce) {
    // 90 headers x 8000 bytes — comfortably inside MAX_HEADERS_COUNT (100) and
    // MAX_HEADER_VALUE_LENGTH (8192), i.e. a request the server must accept.
    const std::string raw = big_header_block(90, 8000);
    ASSERT_GT(raw.size(), std::size_t{700000});

    ServerFakeIO   io;
    PeekableServer proto(io);

    constexpr std::size_t kSegment = 64;

    // --- half the block, one segment at a time -----------------------------------------------
    const std::size_t half = raw.size() / 2;
    for (std::size_t off = 0; off < half; off += kSegment) {
        const auto n = std::min(kSegment, half - off);
        feed(io, std::string_view(raw.data() + off, n));
        ASSERT_EQ(step(proto, io), 0u) << "the header block is not complete yet";
    }

    // THE oracle: parsing is incremental, so roughly half the headers are already committed.
    // Reset-and-re-feed throws this state away on every arrival, leaving it empty — which is
    // exactly the shape whose cost is quadratic.
    EXPECT_GT(proto.peek().headers().size(), std::size_t{10})
        << "the parser was reset between arrivals: the whole buffer is being re-parsed every time, "
           "which is O(n^2) in the header-block size and remotely triggerable";

    // --- the rest ------------------------------------------------------------------------------
    std::size_t framed = 0;
    for (std::size_t off = half; off < raw.size(); off += kSegment) {
        const auto n = std::min(kSegment, raw.size() - off);
        feed(io, std::string_view(raw.data() + off, n));
        framed = step(proto, io);
        if (framed)
            break;
    }

    ASSERT_GT(framed, 0u) << "the request must frame once its header block is complete";
    ASSERT_EQ(io.request_count, 1);
    EXPECT_EQ(io.last_request->uri().path(), "/linear");
    // Every header survived the incremental parse exactly once — the property the old reset() was
    // there to protect, now upheld by the append-based callbacks instead.
    EXPECT_EQ(io.last_request->header("X-Pad-0"), std::string(8000, 'v'));
    EXPECT_EQ(io.last_request->header("X-Pad-89"), std::string(8000, 'v'));
    EXPECT_EQ(io.last_request->headers().find("X-Pad-42")->second.size(), 1u) << "a header must be committed once, not once per re-parse";
}

// ===========================================================================
// The typed Content-Type a dispatched message carries agrees with its raw header on
// EVERY framing path.
//
// The header callbacks fill the raw map; the typed cache (content_type()) was refreshed
// only by the parser's on_message_complete, which runs on the chunked path alone. The
// Content-Length, empty-body, HEAD and close-delimited paths frame in the protocol and
// hand the message over without that callback, so content_type() kept the defaults
// whatever the peer sent (Huly QB-506). The refresh now happens where the header section
// ends, which every path crosses. on_message_complete also re-wrote the header through
// set_content_type(), adding an EMPTY Content-Type to a chunked message that had none.
// ===========================================================================

namespace {

void
expect_typed_content_type(qb::http::Headers const &msg, std::string_view type, std::string_view charset, const char *path) {
    EXPECT_EQ(msg.content_type().type(), type) << path;
    EXPECT_EQ(msg.content_type().charset(), charset) << path;
}

} // namespace

TEST(Http1ProtocolFraming, TypedContentTypeMatchesTheRawHeaderOnEveryFramingPath) {
    const std::string ct    = "Content-Type: application/problem+json; charset=utf-16\r\n";
    const auto        typed = [](qb::http::Headers const &msg, const char *path) {
        EXPECT_EQ(msg.header("Content-Type"), "application/problem+json; charset=utf-16") << path << ": raw header";
        expect_typed_content_type(msg, "application/problem+json", "utf-16", path);
    };

    {
        ServerFakeIO                             io;
        qb::protocol::http::server<ServerFakeIO> proto(io);
        feed(io, "POST /a HTTP/1.1\r\n" + ct + "Content-Length: 3\r\n\r\nabc");
        ASSERT_GT(step(proto, io), 0u);
        ASSERT_TRUE(io.last_request.has_value());
        typed(*io.last_request, "request, Content-Length");
    }
    {
        ServerFakeIO                             io;
        qb::protocol::http::server<ServerFakeIO> proto(io);
        feed(io, "GET /b HTTP/1.1\r\n" + ct + "\r\n");
        ASSERT_GT(step(proto, io), 0u);
        ASSERT_TRUE(io.last_request.has_value());
        typed(*io.last_request, "request, no body");
    }
    {
        ServerFakeIO                             io;
        qb::protocol::http::server<ServerFakeIO> proto(io);
        feed(io, "POST /c HTTP/1.1\r\n" + ct + "Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n");
        ASSERT_GT(step(proto, io), 0u);
        ASSERT_TRUE(io.last_request.has_value());
        typed(*io.last_request, "request, chunked (control)");
        EXPECT_EQ(io.last_request->headers().at("content-type").size(), 1u);
    }
    {
        ClientFakeIO                             io;
        qb::protocol::http::client<ClientFakeIO> proto(io);
        feed(io, "HTTP/1.1 200 OK\r\n" + ct + "Content-Length: 2\r\n\r\nok");
        ASSERT_GT(step(proto, io), 0u);
        ASSERT_TRUE(io.last_response.has_value());
        typed(*io.last_response, "response, Content-Length");
    }
    {
        ClientFakeIO io;
        io.body_forbidden = true;
        qb::protocol::http::client<ClientFakeIO> proto(io);
        feed(io, "HTTP/1.1 200 OK\r\n" + ct + "Content-Length: 42\r\n\r\n");
        ASSERT_GT(step(proto, io), 0u);
        ASSERT_TRUE(io.last_response.has_value());
        typed(*io.last_response, "response to HEAD");
    }
    {
        ClientFakeIO                             io;
        qb::protocol::http::client<ClientFakeIO> proto(io);
        feed(io, "HTTP/1.1 200 OK\r\n" + ct + "\r\nclose-delimited");
        ASSERT_EQ(step(proto, io), 0u);
        proto.flush_eof();
        ASSERT_TRUE(io.last_response.has_value());
        typed(*io.last_response, "response, close-delimited");
    }
    {
        ClientFakeIO                             io;
        qb::protocol::http::client<ClientFakeIO> proto(io);
        feed(io, "HTTP/1.1 200 OK\r\n" + ct + "Transfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n");
        ASSERT_GT(step(proto, io), 0u);
        ASSERT_TRUE(io.last_response.has_value());
        typed(*io.last_response, "response, chunked (control)");
    }
}

TEST(Http1ProtocolFraming, ConsecutiveMessagesEachCarryTheirOwnContentType) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);
    feed(io, "POST /1 HTTP/1.1\r\nContent-Type: text/csv; charset=iso-8859-1\r\nContent-Length: 1\r\n\r\nx"
             "GET /2 HTTP/1.1\r\nHost: h\r\n\r\n"
             "POST /3 HTTP/1.1\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n1\r\ny\r\n0\r\n\r\n"
             "POST /4 HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nz\r\n0\r\n\r\n");

    ASSERT_GT(step(proto, io), 0u);
    ASSERT_TRUE(io.last_request.has_value());
    expect_typed_content_type(*io.last_request, "text/csv", "iso-8859-1", "first message");

    ASSERT_GT(step(proto, io), 0u);
    expect_typed_content_type(*io.last_request, qb::http::Headers::default_content_type, qb::http::Headers::default_charset,
                              "second message, no Content-Type: the defaults, nothing left over");
    EXPECT_FALSE(io.last_request->has_header("Content-Type"));

    ASSERT_GT(step(proto, io), 0u);
    expect_typed_content_type(*io.last_request, "application/json", qb::http::Headers::default_charset, "third message, chunked");

    ASSERT_GT(step(proto, io), 0u);
    EXPECT_EQ(io.request_count, 4);
    expect_typed_content_type(*io.last_request, qb::http::Headers::default_content_type, qb::http::Headers::default_charset,
                              "fourth message, chunked without Content-Type");
    EXPECT_FALSE(io.last_request->has_header("Content-Type")) << "a chunked message gained a Content-Type header the peer never sent";
}

// An empty chunked body is framed by its last-chunk alone (RFC 9112 §7.1), so what the
// serializer emits for it must frame on the peer BEFORE the next message on the same
// connection (Huly QB-493): without the last-chunk the peer reads the next message's
// start line as a chunk size and the connection fails.
TEST(Http1ProtocolFraming, EmptyChunkedMessagesFrameBeforeTheNextOne) {
    {
        qb::http::Request empty{qb::http::method::POST, {"http://example.test/empty"}};
        empty.set_header("Transfer-Encoding", "chunked");
        qb::http::Request next{qb::http::method::GET, {"http://example.test/next"}};

        qb::allocator::pipe<char> wire;
        ASSERT_NO_THROW(wire << empty << next);

        ServerFakeIO                             io;
        qb::protocol::http::server<ServerFakeIO> proto(io);
        feed(io, std::string_view(wire.begin(), wire.size()));

        ASSERT_GT(step(proto, io), 0u) << "the empty chunked request never completed";
        ASSERT_TRUE(io.last_request.has_value());
        EXPECT_EQ(io.last_request->uri().path(), "/empty");
        EXPECT_EQ(io.last_request->body().size(), 0u);
        ASSERT_GT(step(proto, io), 0u);
        EXPECT_TRUE(proto.ok());
        EXPECT_EQ(io.request_count, 2);
        EXPECT_EQ(io.last_request->uri().path(), "/next");
        EXPECT_EQ(io.input.size(), 0u);
    }
    {
        qb::http::Response empty;
        empty.status() = qb::http::status::OK;
        empty.set_header("Transfer-Encoding", "chunked");
        qb::http::Response next;
        next.status() = qb::http::status::ACCEPTED;
        next.body()   = "second";

        qb::allocator::pipe<char> wire;
        ASSERT_NO_THROW(wire << empty << next);

        ClientFakeIO                             io;
        qb::protocol::http::client<ClientFakeIO> proto(io);
        feed(io, std::string_view(wire.begin(), wire.size()));

        ASSERT_GT(step(proto, io), 0u) << "the empty chunked response never completed";
        ASSERT_TRUE(io.last_response.has_value());
        EXPECT_EQ(io.last_response->status(), 200);
        EXPECT_EQ(io.last_response->body().size(), 0u);
        ASSERT_GT(step(proto, io), 0u);
        EXPECT_TRUE(proto.ok());
        EXPECT_EQ(io.response_count, 2);
        EXPECT_EQ(io.last_response->status(), 202);
        EXPECT_EQ(io.last_response->body().as<std::string>(), "second");
    }
}

// The other half of the same contract: a body streamed by hand writes the message's HEAD
// (qb::http::MessageHead), then its chunks and the terminating Chunk{}. The peer frames it as
// one message and the next one stays intact.
TEST(Http1ProtocolFraming, AHandStreamedChunkedBodyFramesAfterItsHead) {
    qb::http::Request upload{qb::http::method::POST, {"http://example.test/stream"}};
    upload.set_header("Transfer-Encoding", "chunked");
    qb::http::Request next{qb::http::method::GET, {"http://example.test/after"}};

    qb::allocator::pipe<char> wire;
    wire << qb::http::MessageHead{upload};
    wire << qb::http::Chunk("part-1|", 7) << qb::http::Chunk("part-2", 6) << qb::http::Chunk();
    wire << next;

    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);
    feed(io, std::string_view(wire.begin(), wire.size()));

    ASSERT_GT(step(proto, io), 0u);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_EQ(io.last_request->uri().path(), "/stream");
    EXPECT_EQ(io.last_request->body().as<std::string>(), "part-1|part-2");
    ASSERT_GT(step(proto, io), 0u);
    EXPECT_TRUE(proto.ok());
    EXPECT_EQ(io.request_count, 2);
    EXPECT_EQ(io.last_request->uri().path(), "/after");
}

// ===========================================================================
// Chunked trailer sections (Huly QB-1067)
//
// The parser stored a field when the NEXT field began or when the header section ended; a trailer
// section has neither after its last field, so the last trailer field was dropped -- the only one,
// for a one-field trailer. Received trailer fields reach the message the way HTTP/2 and HTTP/3
// surface theirs: through the ordinary header API (readme 19). A field a trailer section must not
// carry -- framing, connection management, routing -- refuses the message, as HTTP/2 and HTTP/3
// refuse their stream: merged, a trailer `Content-Length` would sit beside the chunked framing.
// ===========================================================================

namespace {

constexpr std::string_view kTrailedRequest = "POST /up HTTP/1.1\r\nHost: x\r\nX-Empty-Head:\r\nTransfer-Encoding: chunked\r\n"
                                             "Trailer: X-Checksum, X-Note, X-Count\r\n\r\n"
                                             "5\r\nhello\r\n0\r\n"
                                             "X-Checksum: abc\r\nX-Note:\r\nX-Count: 2\r\n\r\n";

} // namespace

TEST(Http1ProtocolFraming, EveryChunkedTrailerFieldReachesTheMessage) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);
    feed(io, kTrailedRequest);
    feed(io, "GET /next HTTP/1.1\r\nHost: x\r\n\r\n");

    ASSERT_GT(step(proto, io), 0u);
    ASSERT_TRUE(proto.ok());
    ASSERT_EQ(io.request_count, 1);
    EXPECT_EQ(io.last_request->body().as<std::string>(), "hello");
    EXPECT_EQ(io.last_request->header("X-Checksum"), "abc");
    EXPECT_EQ(io.last_request->header("X-Count"), "2") << "the last trailer field must not be dropped";
    // An empty value is a value: the field is there, empty, and the next name stays its own.
    EXPECT_TRUE(io.last_request->has_header("X-Note"));
    EXPECT_EQ(io.last_request->header("X-Note"), "");
    EXPECT_TRUE(io.last_request->has_header("X-Empty-Head"));
    EXPECT_EQ(io.last_request->header("Transfer-Encoding"), "chunked");
    // The trailer section is the message's trailers(), apart from its header section (Huly QB-1073);
    // the header fields above keep it too, for 3.x source compatibility.
    const auto &trailers = io.last_request->trailers();
    EXPECT_EQ(trailers.header_count(), 3u);
    EXPECT_EQ(trailers.header("X-Checksum"), "abc");
    EXPECT_EQ(trailers.header("x-count"), "2");
    EXPECT_TRUE(trailers.has_header("X-Note"));
    EXPECT_FALSE(trailers.has_header("X-Empty-Head")) << "a header-section field is not a trailer field";
    EXPECT_FALSE(trailers.has_header("Trailer"));
    EXPECT_FALSE(trailers.has_header("Host"));

    // The next message starts clean: no trailer field of the previous one leaks into it.
    ASSERT_GT(step(proto, io), 0u);
    ASSERT_EQ(io.request_count, 2);
    EXPECT_EQ(io.last_request->uri().path(), "/next");
    EXPECT_FALSE(io.last_request->has_header("X-Count"));
    EXPECT_FALSE(io.last_request->has_header("X-Checksum"));
    EXPECT_FALSE(io.last_request->has_trailers());

    // A response's trailer section, on the client side, alike -- a one-field one included.
    ClientFakeIO                             cio;
    qb::protocol::http::client<ClientFakeIO> cproto(cio);
    feed(cio, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Server-Timing\r\n\r\n"
              "4\r\nWiki\r\n0\r\nServer-Timing: db;dur=53\r\n\r\n");
    ASSERT_GT(step(cproto, cio), 0u);
    ASSERT_TRUE(cproto.ok());
    ASSERT_EQ(cio.response_count, 1);
    EXPECT_EQ(cio.last_response->body().as<std::string>(), "Wiki");
    EXPECT_EQ(cio.last_response->header("Server-Timing"), "db;dur=53");
    EXPECT_EQ(cio.last_response->trailers().header_count(), 1u);
    EXPECT_EQ(cio.last_response->trailers().header("Server-Timing"), "db;dur=53");
}

// Every field of the one trailer list HTTP/1.1, HTTP/2 and HTTP/3 share
// (qb::http::detail::is_forbidden_trailer_field) refuses the message -- `HTTP2-Settings` included,
// which HTTP/2 refused and HTTP/1.1 accepted (Huly QB-1073).
TEST(Http1ProtocolFraming, ATrailerFieldThatFramesOrRoutesRefusesTheMessage) {
    for (const char *field :
         {"Content-Length: 5", "Transfer-Encoding: chunked", "Trailer: X-A", "Host: elsewhere.test", "Connection: close", "TE: trailers",
          "Upgrade: h2c", "Keep-Alive: timeout=5", "Proxy-Connection: close", "Proxy-Authenticate: Basic",
          "Proxy-Authorization: Basic eA==", "HTTP2-Settings: AAMAAABk"}) {
        // First and last in its trailer section, so both storing paths are covered.
        for (const bool last : {true, false}) {
            ServerFakeIO                             io;
            qb::protocol::http::server<ServerFakeIO> proto(io);
            std::string                              raw = "POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                                                           "5\r\nhello\r\n0\r\n";
            raw += field;
            raw += "\r\n";
            if (!last)
                raw += "X-After: 1\r\n";
            raw += "\r\n";
            feed(io, raw);
            (void) step(proto, io);
            EXPECT_FALSE(proto.ok()) << field << (last ? " (last)" : " (not last)");
            EXPECT_EQ(io.request_count, 0) << field << (last ? " (last)" : " (not last)") << ": the message must not be dispatched";
        }
    }

    // An ordinary field is not refused, whatever its name looks like.
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);
    feed(io, "POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Content-Length-Hint: 5\r\n\r\n");
    ASSERT_GT(step(proto, io), 0u);
    EXPECT_TRUE(proto.ok());
    EXPECT_EQ(io.last_request->header("X-Content-Length-Hint"), "5");
}

TEST(Http1ProtocolFraming, AnnouncedTrailerFieldsRoundTripThroughTheTrailerSection) {
    qb::http::Request request{qb::http::method::POST, {"http://example.test/up"}};
    request.set_header("Transfer-Encoding", "chunked");
    request.set_header("Trailer", "X-Checksum");
    request.set_header("X-Checksum", "abc");
    request.body() = "hello";

    qb::allocator::pipe<char> wire;
    ASSERT_NO_THROW(wire << request);
    const std::string raw{wire.begin(), wire.size()};
    const auto        head_end = raw.find("\r\n\r\n");
    ASSERT_NE(head_end, std::string::npos);
    EXPECT_EQ(raw.substr(0, head_end).find("x-checksum:"), std::string::npos) << "an announced field leaves the header section: " << raw;

    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);
    feed(io, raw);
    ASSERT_GT(step(proto, io), 0u);
    ASSERT_TRUE(proto.ok());
    EXPECT_EQ(io.last_request->body().as<std::string>(), "hello");
    EXPECT_EQ(io.last_request->header("X-Checksum"), "abc");
    EXPECT_EQ(io.last_request->trailers().header("X-Checksum"), "abc") << "an announced field arrives as a trailer field";
}

// What a chunked message carries in its trailers() is what the peer's parser finds in its own:
// sent after the last chunk, announced by a `Trailer` field the message did not write, an empty
// body included (Huly QB-1073).
TEST(Http1ProtocolFraming, TrailersContainerRoundTripsThroughAChunkedMessage) {
    for (const std::string body : {"hello", ""}) {
        qb::http::Response response;
        response.status() = qb::http::status::OK;
        response.set_header("Transfer-Encoding", "chunked");
        response.body() = body;
        response.trailers().set_header("Server-Timing", "db;dur=53");
        response.trailers().add_header("X-Sum", "a");
        response.trailers().add_header("X-Sum", "b");

        qb::allocator::pipe<char> wire;
        ASSERT_NO_THROW(wire << response);
        const std::string raw{wire.begin(), wire.size()};

        ClientFakeIO                             cio;
        qb::protocol::http::client<ClientFakeIO> cproto(cio);
        feed(cio, raw);
        ASSERT_GT(step(cproto, cio), 0u) << raw;
        ASSERT_TRUE(cproto.ok()) << raw;
        ASSERT_EQ(cio.response_count, 1);
        const auto &received = *cio.last_response;
        EXPECT_EQ(received.body().as<std::string>(), body);
        EXPECT_EQ(received.trailers().header_count(), 2u) << raw;
        EXPECT_EQ(received.trailers().header("server-timing"), "db;dur=53");
        ASSERT_EQ(received.trailers().headers().at("x-sum").size(), 2u);
        EXPECT_EQ(received.trailers().header("x-sum", 1), "b");
        EXPECT_FALSE(received.trailers().has_header("Trailer")) << "the announcement is a header field";
        EXPECT_TRUE(received.has_header("Trailer"));
    }
}

// ===========================================================================
// A request over the server's body cap is ANSWERED, not dropped (Huly QB-168).
//
// The cap used to be the constant protocol_limits::MAX_BODY_SIZE, and a request over it failed the
// parse, which invalidated the protocol: the connection closed with no response at all. The protocol
// now reads the cap from its io when a request begins (`http_request_limits()`, the server's
// `set_request_limits` / `set_max_body_size`) and hands a refusal to the io (`http1_refuse_request(413)`), which answers it
// and closes; the bytes that follow are dropped. An io without the hook keeps the old contract.
// ===========================================================================

namespace {

/// The server session's two hooks, observable: the limits it reports, the refusals it is handed.
struct RefusingServerFakeIO {
    using base_io_t = RefusingServerFakeIO;

    qb::allocator::pipe<char>        input;
    qb::http::request_limits         limits;
    int                              request_count = 0;
    std::optional<qb::http::Request> last_request;
    std::vector<int>                 refusals;

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }

    [[nodiscard]] qb::http::request_limits const &
    http_request_limits() const noexcept {
        return limits;
    }

    void
    http1_refuse_request(qb::http::Status status) noexcept {
        refusals.push_back(status.code());
    }

    void
    on(qb::http::Request &&request) {
        ++request_count;
        last_request = std::move(request);
    }
};

} // namespace

// The default cap, a declared length one byte over it: refused at the end of the header section,
// before a body byte is read, with 413 -- and the protocol stays valid, so the session can answer.
TEST(Http1ProtocolFraming, AContentLengthOverTheCapIsRefusedWith413BeforeTheBody) {
    RefusingServerFakeIO                             io;
    qb::protocol::http::server<RefusingServerFakeIO> proto(io);

    feed(io, "POST /upload HTTP/1.1\r\nHost: h\r\nContent-Length: " + std::to_string(qb::http::protocol_limits::MAX_BODY_SIZE + 1)
                 + "\r\n\r\nfirst body bytes");

    EXPECT_EQ(step(proto, io), 0u);
    EXPECT_EQ(io.request_count, 0) << "a refused request is never dispatched";
    ASSERT_EQ(io.refusals.size(), 1u) << "the request must be handed to the io for an answer, not dropped";
    EXPECT_EQ(io.refusals.front(), 413);
    EXPECT_TRUE(proto.ok()) << "the io answers before the connection ends: the protocol must stay valid";
    EXPECT_EQ(io.input.size(), 0u) << "what followed the refused header section is dropped";
}

// The server's own cap, read live: a request AT it passes, one byte over is refused -- the declared
// length and the bytes a chunked body delivers alike -- and a new value applies to the next request.
TEST(Http1ProtocolFraming, TheServerCapIsReadWhenEachRequestBegins) {
    RefusingServerFakeIO                             io;
    qb::protocol::http::server<RefusingServerFakeIO> proto(io);
    io.limits.max_body_size = 16;

    feed(io, "POST /a HTTP/1.1\r\nContent-Length: 16\r\n\r\n0123456789abcdef");
    EXPECT_GT(step(proto, io), 0u);
    ASSERT_EQ(io.request_count, 1) << "a body exactly at the cap is accepted";
    EXPECT_EQ(io.last_request->body().as<std::string>(), "0123456789abcdef");

    io.limits.max_body_size = 8; // the server lowers it between two requests
    feed(io, "POST /b HTTP/1.1\r\nContent-Length: 9\r\n\r\n012345678");
    EXPECT_EQ(step(proto, io), 0u);
    EXPECT_EQ(io.request_count, 1);
    ASSERT_EQ(io.refusals, std::vector<int>{413}) << "the next request is judged under the new cap";
    EXPECT_TRUE(proto.ok());

    // Everything after the refusal is dropped, a complete valid request included: the connection
    // has lost its framing (the refused body was never read) and ends with the answer.
    feed(io, "GET /c HTTP/1.1\r\nHost: h\r\n\r\n");
    EXPECT_EQ(step(proto, io), 0u);
    EXPECT_EQ(io.request_count, 1);
    EXPECT_EQ(io.refusals.size(), 1u);
    EXPECT_EQ(io.input.size(), 0u);
}

TEST(Http1ProtocolFraming, AChunkedBodyPassingTheCapIsRefusedWith413) {
    RefusingServerFakeIO                             io;
    qb::protocol::http::server<RefusingServerFakeIO> proto(io);
    io.limits.max_body_size = 8;

    feed(io, "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n01234567\r\n0\r\n\r\n");
    EXPECT_GT(step(proto, io), 0u);
    ASSERT_EQ(io.request_count, 1) << "a chunked body exactly at the cap is accepted";
    EXPECT_EQ(io.last_request->body().as<std::string>(), "01234567");

    feed(io, "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n01234\r\n");
    EXPECT_EQ(step(proto, io), 0u);
    EXPECT_TRUE(io.refusals.empty()) << "5 bytes of 8: not yet";
    feed(io, "4\r\n5678\r\n");
    EXPECT_EQ(step(proto, io), 0u);
    ASSERT_EQ(io.refusals, std::vector<int>{413}) << "the ninth byte passes the cap";
    EXPECT_EQ(io.request_count, 1);
    EXPECT_TRUE(proto.ok());
}

// 0 means no cap of the protocol's own: a length past the default constant is framed normally.
TEST(Http1ProtocolFraming, AZeroCapLeavesTheBodyUnbounded) {
    RefusingServerFakeIO                             io;
    qb::protocol::http::server<RefusingServerFakeIO> proto(io);
    io.limits.max_body_size = 0;

    feed(io, "POST /big HTTP/1.1\r\nContent-Length: " + std::to_string(qb::http::protocol_limits::MAX_BODY_SIZE + 1) + "\r\n\r\nxyz");
    EXPECT_EQ(step(proto, io), 0u) << "the body is still arriving";
    EXPECT_TRUE(io.refusals.empty());
    EXPECT_TRUE(proto.ok());
}

// An io that cannot answer (no http1_refuse_request) keeps the contract it had: the protocol is
// invalidated and the connection closes.
TEST(Http1ProtocolFraming, AnIoThatCannotAnswerStillClosesOnAnOversizedRequest) {
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);

    feed(io, "POST /upload HTTP/1.1\r\nContent-Length: " + std::to_string(qb::http::protocol_limits::MAX_BODY_SIZE + 1) + "\r\n\r\n");
    EXPECT_EQ(proto.getMessageSize(), 0u);
    EXPECT_FALSE(proto.ok());
    EXPECT_EQ(io.request_count, 0);
}

// ===========================================================================
// The server's request limits (Huly QB-94), each in both polarities: a request exactly at a limit is
// served, one byte (or one field) over is handed to the io for its answer -- 414 for the target, 431
// for a field name, a field value or a section's field count, 413 for a chunk. They used to be
// constants, and a breach closed the connection with no answer. A trailer section counts its fields on
// its own, as HTTP/2 and HTTP/3 count theirs; 0 means no limit of that kind.
// ===========================================================================

namespace {

/// What one exchange under @p limits produced: the requests dispatched, the refusals handed to the io.
struct LimitOutcome {
    int              requests = 0;
    std::vector<int> refusals;
    bool             ok = true;
};

LimitOutcome
serve_under(qb::http::request_limits const &limits, std::string const &wire) {
    RefusingServerFakeIO                             io;
    qb::protocol::http::server<RefusingServerFakeIO> proto(io);
    io.limits = limits;
    feed(io, wire);
    while (step(proto, io) > 0) {
    }
    return {io.request_count, io.refusals, proto.ok()};
}

std::string
get_request(std::string const &target, std::string const &fields = "") {
    return "GET " + target + " HTTP/1.1\r\nHost: h\r\n" + fields + "\r\n";
}

} // namespace

TEST(Http1ProtocolFraming, TheTargetLimitIsAnswered414) {
    qb::http::request_limits limits;
    limits.max_url_length = 16;

    const auto at = serve_under(limits, get_request("/" + std::string(15, 'a')));
    EXPECT_EQ(at.requests, 1) << "a target of exactly 16 bytes is served";
    EXPECT_TRUE(at.refusals.empty());

    const auto over = serve_under(limits, get_request("/" + std::string(16, 'a')));
    EXPECT_EQ(over.requests, 0);
    EXPECT_EQ(over.refusals, std::vector<int>{414});
    EXPECT_TRUE(over.ok) << "the io answers before the connection ends";
}

TEST(Http1ProtocolFraming, TheFieldNameLimitIsAnswered431) {
    qb::http::request_limits limits;
    limits.max_header_name_length = 8;

    const auto at = serve_under(limits, get_request("/", "x-abcdef: v\r\n"));
    EXPECT_EQ(at.requests, 1) << "a name of exactly 8 bytes is served";
    EXPECT_TRUE(at.refusals.empty());

    const auto over = serve_under(limits, get_request("/", "x-abcdefg: v\r\n"));
    EXPECT_EQ(over.requests, 0);
    EXPECT_EQ(over.refusals, std::vector<int>{431});
}

TEST(Http1ProtocolFraming, TheFieldValueLimitIsAnswered431) {
    qb::http::request_limits limits;
    limits.max_header_value_length = 8;

    const auto at = serve_under(limits, get_request("/", "x-v: 12345678\r\n"));
    EXPECT_EQ(at.requests, 1) << "a value of exactly 8 bytes is served";
    EXPECT_TRUE(at.refusals.empty());

    const auto over = serve_under(limits, get_request("/", "x-v: 123456789\r\n"));
    EXPECT_EQ(over.requests, 0);
    EXPECT_EQ(over.refusals, std::vector<int>{431});

    // The last field of the section is judged at its end, not only when the next one begins.
    const auto last = serve_under(limits, "GET / HTTP/1.1\r\nx-v: 123456789\r\n\r\n");
    EXPECT_EQ(last.refusals, std::vector<int>{431});
}

TEST(Http1ProtocolFraming, TheFieldCountLimitIsAnswered431) {
    qb::http::request_limits limits;
    limits.max_headers_count = 3;

    const auto at = serve_under(limits, get_request("/", "a: 1\r\nb: 2\r\n")); // Host, a, b
    EXPECT_EQ(at.requests, 1) << "exactly 3 fields are served";
    EXPECT_TRUE(at.refusals.empty());

    const auto over = serve_under(limits, get_request("/", "a: 1\r\nb: 2\r\nc: 3\r\n"));
    EXPECT_EQ(over.requests, 0);
    EXPECT_EQ(over.refusals, std::vector<int>{431});
}

TEST(Http1ProtocolFraming, TheChunkLimitIsAnswered413) {
    qb::http::request_limits limits;
    limits.max_chunk_size = 8;

    const auto at = serve_under(limits, "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n01234567\r\n0\r\n\r\n");
    EXPECT_EQ(at.requests, 1) << "a chunk of exactly 8 bytes is served";
    EXPECT_TRUE(at.refusals.empty());

    const auto over = serve_under(limits, "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n012345678\r\n0\r\n\r\n");
    EXPECT_EQ(over.requests, 0);
    EXPECT_EQ(over.refusals, std::vector<int>{413});
}

// A trailer section is a section of its own: its field count starts again, its fields are held to the same
// name and value limits, and a breach there is answered 431 too.
TEST(Http1ProtocolFraming, ATrailerSectionIsHeldToTheFieldLimitsOnItsOwn) {
    qb::http::request_limits limits;
    limits.max_headers_count       = 2;
    limits.max_header_value_length = 8;
    const std::string head         = "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n"; // 1 field

    const auto at = serve_under(limits, head + "x-a: 1\r\nx-b: 12345678\r\n\r\n");
    EXPECT_EQ(at.requests, 1) << "1 header field, then 2 trailer fields: each section within its limit";
    EXPECT_TRUE(at.refusals.empty());

    const auto count_over = serve_under(limits, head + "x-a: 1\r\nx-b: 2\r\nx-c: 3\r\n\r\n");
    EXPECT_EQ(count_over.requests, 0);
    EXPECT_EQ(count_over.refusals, std::vector<int>{431});

    const auto value_over = serve_under(limits, head + "x-a: 123456789\r\n\r\n");
    EXPECT_EQ(value_over.requests, 0);
    EXPECT_EQ(value_over.refusals, std::vector<int>{431});
}

// 0 means no limit of that kind: a target and a value past the default constants are served.
TEST(Http1ProtocolFraming, ZeroRequestLimitsMeanNone) {
    qb::http::request_limits limits{0, 0, 0, 0, 0, 0};

    const auto out =
        serve_under(limits, get_request("/" + std::string(qb::http::protocol_limits::MAX_URL_LENGTH, 'u'),
                                        "x-v: " + std::string(qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'v') + "\r\n"));
    EXPECT_EQ(out.requests, 1);
    EXPECT_TRUE(out.refusals.empty());
}

// The defaults are the constants: a server that never set its limits answers a target one byte past
// MAX_URL_LENGTH with 414 (it used to close with no answer).
TEST(Http1ProtocolFraming, TheDefaultLimitsAreTheConstants) {
    const auto at = serve_under({}, get_request("/" + std::string(qb::http::protocol_limits::MAX_URL_LENGTH - 1, 'u')));
    EXPECT_EQ(at.requests, 1);
    const auto over = serve_under({}, get_request("/" + std::string(qb::http::protocol_limits::MAX_URL_LENGTH, 'u')));
    EXPECT_EQ(over.refusals, std::vector<int>{414});
}

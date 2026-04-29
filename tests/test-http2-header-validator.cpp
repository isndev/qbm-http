#include <gtest/gtest.h>

#include "../2/protocol/base.h"
#include "../2/protocol/client.h"
#include "../2/protocol/server.h"

namespace {

struct Http2ProtocolHarness {
    using base_io_t = Http2ProtocolHarness;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;
    int request_count = 0;
    int response_count = 0;
    int stream_error_count = 0;
    int goaway_count = 0;
    qb::protocol::http2::ErrorCode last_stream_error = qb::protocol::http2::ErrorCode::NO_ERROR;
    qb::protocol::http2::ErrorCode last_goaway_error = qb::protocol::http2::ErrorCode::NO_ERROR;

    qb::allocator::pipe<char>& in() noexcept { return input; }
    qb::allocator::pipe<char>& out() noexcept { return output; }

    template <typename Frame>
    Http2ProtocolHarness& operator<<(const Frame& frame) {
        output.put(frame);
        return *this;
    }

    void on(qb::http::Request&&, uint32_t) {
        ++request_count;
    }

    void on(qb::http::Response&&, uint64_t) {
        ++response_count;
    }

    void on(const qb::protocol::http2::Http2StreamErrorEvent& event) {
        ++stream_error_count;
        last_stream_error = event.error_code;
    }

    void on(const qb::protocol::http2::Http2GoAwayEvent& event) {
        ++goaway_count;
        last_goaway_error = event.error_code;
    }
};

[[nodiscard]] std::vector<uint8_t> encode_hpack_headers(
    const std::vector<qb::protocol::hpack::HeaderField>& headers) {
    qb::protocol::hpack::Encoder encoder;
    std::vector<uint8_t> encoded;
    EXPECT_TRUE(encoder.encode(headers, encoded));
    return encoded;
}

} // namespace

TEST(HTTP2HeaderValidator, RejectsUnknownRequestPseudoHeaders) {
    std::vector<qb::protocol::hpack::HeaderField> headers{
        {":method", "GET"},
        {":scheme", "https"},
        {":path", "/"},
        {":protocol", "websocket"}
    };

    const auto result = qb::protocol::http2::HeaderValidator::validate_request_pseudo_headers(headers);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2HeaderValidator, RejectsConnectionSpecificRequestHeaders) {
    EXPECT_TRUE(qb::protocol::http2::HeaderValidator::is_forbidden_header("connection"));
    EXPECT_TRUE(qb::protocol::http2::HeaderValidator::is_forbidden_header("host"));
    EXPECT_TRUE(qb::protocol::http2::HeaderValidator::is_forbidden_header("transfer-encoding"));
}

TEST(HTTP2HeaderValidator, AllowsTeToBeValidatedByValue) {
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::is_forbidden_header("te"));
}

TEST(HTTP2HeaderValidator, ForbidsTeInResponses) {
    EXPECT_TRUE(qb::protocol::http2::HeaderValidator::is_forbidden_response_header("te"));
}

TEST(HTTP2HeaderValidator, ForbidsTeAndTrailerInTrailers) {
    EXPECT_TRUE(qb::protocol::http2::HeaderValidator::is_forbidden_trailer_header("te"));
    EXPECT_TRUE(qb::protocol::http2::HeaderValidator::is_forbidden_trailer_header("trailer"));
    EXPECT_TRUE(qb::protocol::http2::HeaderValidator::is_forbidden_trailer_header("content-length"));
}

TEST(HTTP2HeaderValidator, TeRequestValueValidationAcceptsTrailersWithOws) {
    EXPECT_TRUE(qb::protocol::http2::HeaderValidator::is_valid_request_te_value("trailers"));
    EXPECT_TRUE(qb::protocol::http2::HeaderValidator::is_valid_request_te_value(" trailers "));
    EXPECT_TRUE(qb::protocol::http2::HeaderValidator::is_valid_request_te_value("trailers, trailers"));
}

TEST(HTTP2HeaderValidator, TeRequestValueValidationRejectsOtherTokens) {
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::is_valid_request_te_value(""));
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::is_valid_request_te_value("gzip"));
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::is_valid_request_te_value("trailers, gzip"));
}

TEST(HTTP2HeaderValidator, AllowsContentLengthInResponseHeaders) {
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::is_forbidden_response_header("content-length"));
}

TEST(HTTP2HeaderValidator, RejectsUnknownResponsePseudoHeaders) {
    std::vector<qb::protocol::hpack::HeaderField> headers{
        {":status", "200"},
        {":path", "/illegal-in-response"}
    };

    const auto result = qb::protocol::http2::HeaderValidator::validate_response_pseudo_headers(headers);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2HeaderValidator, RequiresStatusPseudoHeaderInResponse) {
    std::vector<qb::protocol::hpack::HeaderField> headers{
        {"content-type", "text/plain"}
    };

    const auto result = qb::protocol::http2::HeaderValidator::validate_response_pseudo_headers(headers);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2HeaderValidator, ValidHeaderFieldFormatAcceptsLowercaseToken) {
    EXPECT_TRUE(qb::protocol::http2::HeaderValidator::is_valid_header_field("content-type", "text/plain"));
}

TEST(HTTP2HeaderValidator, RejectsUppercaseHeaderName) {
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::is_valid_header_field("Content-Type", "text/plain"));
}

TEST(HTTP2HeaderValidator, RejectsHeaderValueWithCRLF) {
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::is_valid_header_field("x-test", "line1\r\nline2"));
}

TEST(HTTP2HeaderValidator, StrictStatusParsingAcceptsValidThreeDigits) {
    const auto parsed = qb::protocol::http2::detail::parse_status_code("200");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, 200);
}

TEST(HTTP2HeaderValidator, StrictStatusParsingRejectsNonThreeDigitsOrDecoratedForms) {
    EXPECT_FALSE(qb::protocol::http2::detail::parse_status_code("99").has_value());
    EXPECT_FALSE(qb::protocol::http2::detail::parse_status_code("1000").has_value());
    EXPECT_FALSE(qb::protocol::http2::detail::parse_status_code("+200").has_value());
    EXPECT_FALSE(qb::protocol::http2::detail::parse_status_code("200 ").has_value());
    EXPECT_FALSE(qb::protocol::http2::detail::parse_status_code("2O0").has_value());
}

TEST(HTTP2HeaderValidator, StrictContentLengthParsingAcceptsDigitsWithOws) {
    const auto parsed = qb::protocol::http2::HeaderValidator::parse_content_length(" 00123\t");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, 123u);
}

TEST(HTTP2HeaderValidator, StrictContentLengthParsingRejectsInvalidForms) {
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::parse_content_length("").has_value());
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::parse_content_length("-1").has_value());
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::parse_content_length("+1").has_value());
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::parse_content_length("1.0").has_value());
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::parse_content_length("1, 1").has_value());
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::parse_content_length("18446744073709551616").has_value());
}

TEST(HTTP2ServerProtocol, RejectsDataOnIdleStreamAsConnectionError) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ServerHttp2Protocol<Http2ProtocolHarness> protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::DataFrame> data;
    data.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::DATA);
    data.header.flags = qb::protocol::http2::FLAG_END_STREAM;
    data.header.set_stream_id(1);
    data.payload.data_payload = {'x'};

    protocol.on(std::move(data));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, RejectsRstStreamOnIdleStreamAsConnectionError) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ServerHttp2Protocol<Http2ProtocolHarness> protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::RstStreamFrame> rst;
    rst.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::RST_STREAM);
    rst.header.set_stream_id(1);
    rst.payload.error_code = qb::protocol::http2::ErrorCode::CANCEL;

    protocol.on(std::move(rst));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, RejectsWindowUpdateOnIdleStreamAsConnectionError) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ServerHttp2Protocol<Http2ProtocolHarness> protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::WindowUpdateFrame> window_update;
    window_update.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::WINDOW_UPDATE);
    window_update.header.set_stream_id(1);
    window_update.payload.window_size_increment = 1;

    protocol.on(std::move(window_update));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, RejectsRequestBodyShorterThanContentLengthOnDataEndStream) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ServerHttp2Protocol<Http2ProtocolHarness> protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame> headers;
    headers.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::HEADERS);
    headers.header.flags = qb::protocol::http2::FLAG_END_HEADERS;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers({
        {":method", "POST"},
        {":scheme", "https"},
        {":path", "/mismatch"},
        {"content-length", "5"}
    });

    protocol.on(std::move(headers));
    ASSERT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::DataFrame> data;
    data.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::DATA);
    data.header.flags = qb::protocol::http2::FLAG_END_STREAM;
    data.header.set_stream_id(1);
    data.payload.data_payload = {'a', 'b', 'c'};

    protocol.on(std::move(data));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, RejectsOutgoingResponseContentLengthMismatch) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ServerHttp2Protocol<Http2ProtocolHarness> protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame> headers;
    headers.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::HEADERS);
    headers.header.flags = qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers({
        {":method", "GET"},
        {":scheme", "https"},
        {":path", "/mismatch"}
    });

    protocol.on(std::move(headers));
    ASSERT_EQ(io.request_count, 1);

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body() = "abc";
    response.set_header("content-length", "5");

    EXPECT_FALSE(protocol.send_response(1, response));
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, AllowsHeadResponseContentLengthMetadata) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ServerHttp2Protocol<Http2ProtocolHarness> protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame> headers;
    headers.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::HEADERS);
    headers.header.flags = qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers({
        {":method", "HEAD"},
        {":scheme", "https"},
        {":path", "/head"}
    });

    protocol.on(std::move(headers));
    ASSERT_EQ(io.request_count, 1);

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("content-length", "123");

    EXPECT_TRUE(protocol.send_response(1, response));
    EXPECT_EQ(io.stream_error_count, 0);
}

TEST(HTTP2ClientProtocol, GracefulGoawayKeepsAcceptedStreamsAlive) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ClientHttp2Protocol<Http2ProtocolHarness> protocol(io);

    qb::http::Request first;
    first.method() = qb::http::method::GET;
    first.uri() = qb::io::uri("https://example.test/first");

    qb::http::Request second;
    second.method() = qb::http::method::GET;
    second.uri() = qb::io::uri("https://example.test/second");

    ASSERT_TRUE(protocol.send_request(std::move(first), 1));
    ASSERT_TRUE(protocol.send_request(std::move(second), 2));
    ASSERT_EQ(protocol.last_initiated_stream_id(), 3u);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::GoAwayFrame> goaway;
    goaway.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::GOAWAY);
    goaway.header.set_stream_id(0);
    goaway.payload.last_stream_id = 1;
    goaway.payload.error_code = qb::protocol::http2::ErrorCode::NO_ERROR;

    protocol.on(std::move(goaway));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, qb::protocol::http2::ErrorCode::NO_ERROR);
    EXPECT_EQ(io.response_count, 0);
}

TEST(HTTP2ClientProtocol, RejectsRstStreamOnIdleClientStreamAsConnectionError) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ClientHttp2Protocol<Http2ProtocolHarness> protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::RstStreamFrame> rst;
    rst.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::RST_STREAM);
    rst.header.set_stream_id(1);
    rst.payload.error_code = qb::protocol::http2::ErrorCode::CANCEL;

    protocol.on(std::move(rst));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ClientProtocol, RejectsHeadersOnIdleClientStreamAsConnectionError) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ClientHttp2Protocol<Http2ProtocolHarness> protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame> headers;
    headers.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::HEADERS);
    headers.header.flags = qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers({
        {":status", "200"}
    });

    protocol.on(std::move(headers));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ClientProtocol, RejectsWindowUpdateOnIdleClientStreamAsConnectionError) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ClientHttp2Protocol<Http2ProtocolHarness> protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::WindowUpdateFrame> window_update;
    window_update.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::WINDOW_UPDATE);
    window_update.header.set_stream_id(1);
    window_update.payload.window_size_increment = 1;

    protocol.on(std::move(window_update));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
}

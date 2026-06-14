#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

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
        {":authority", "example.test"},
        {":path", "/"},
        {":protocol", "websocket"}
    };

    const auto result = qb::protocol::http2::HeaderValidator::validate_request_pseudo_headers(headers);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2HeaderValidator, RequiresAuthorityPseudoHeaderInRequests) {
    std::vector<qb::protocol::hpack::HeaderField> headers{
        {":method", "GET"},
        {":scheme", "https"},
        {":path", "/"}
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

TEST(HTTP2SettingsValidator, EnableConnectProtocolIsBoolean) {
    using qb::protocol::http2::Http2SettingIdentifier;
    using qb::protocol::http2::SettingsHelper;

    EXPECT_TRUE(SettingsHelper::validate_setting(
        Http2SettingIdentifier::SETTINGS_ENABLE_CONNECT_PROTOCOL, 0, true).is_valid);
    EXPECT_TRUE(SettingsHelper::validate_setting(
        Http2SettingIdentifier::SETTINGS_ENABLE_CONNECT_PROTOCOL, 1, true).is_valid);

    const auto invalid = SettingsHelper::validate_setting(
        Http2SettingIdentifier::SETTINGS_ENABLE_CONNECT_PROTOCOL, 2, true);
    EXPECT_FALSE(invalid.is_valid);
    EXPECT_EQ(invalid.error_code, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
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

TEST(HTTP2HeaderValidator, HeaderValueFormatRejectsControlBytes) {
    EXPECT_TRUE(qb::protocol::http2::HeaderValidator::is_valid_header_value("/safe/path"));
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::is_valid_header_value("/bad\rpath"));
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::is_valid_header_value("/bad\npath"));
    EXPECT_FALSE(qb::protocol::http2::HeaderValidator::is_valid_header_value(std::string_view{"bad\0path", 8}));
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
        {":authority", "example.test"},
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
        {":authority", "example.test"},
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
        {":authority", "example.test"},
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

TEST(HTTP2ServerProtocol, RejectsRequestMissingAuthorityPseudoHeader) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ServerHttp2Protocol<Http2ProtocolHarness> protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame> headers;
    headers.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::HEADERS);
    headers.header.flags = qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers({
        {":method", "GET"},
        {":scheme", "https"},
        {":path", "/missing-authority"}
    });

    protocol.on(std::move(headers));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, RejectsRequestEmptyAuthorityPseudoHeader) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ServerHttp2Protocol<Http2ProtocolHarness> protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame> headers;
    headers.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::HEADERS);
    headers.header.flags = qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers({
        {":method", "GET"},
        {":scheme", "https"},
        {":authority", ""},
        {":path", "/empty-authority"}
    });

    protocol.on(std::move(headers));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, qb::protocol::http2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, PushPromiseRejectsInvalidPromisedStreamId) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ServerHttp2Protocol<Http2ProtocolHarness> protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame> headers;
    headers.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::HEADERS);
    headers.header.flags = qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers({
        {":method", "GET"},
        {":scheme", "https"},
        {":authority", "example.test"},
        {":path", "/parent"}
    });
    protocol.on(std::move(headers));
    ASSERT_EQ(io.request_count, 1);

    qb::http::Request promised{qb::io::uri{"https://example.test/asset"}};
    promised.method() = qb::http::method::GET;

    auto failure = protocol.send_push_promise(1, 3, std::move(promised));
    ASSERT_TRUE(failure.has_value());
    EXPECT_EQ(*failure, qb::protocol::http2::PushPromiseFailureReason::INVALID_PROMISED_STREAM);
}

TEST(HTTP2ServerProtocol, PushPromiseRejectsMissingPromisedAuthority) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ServerHttp2Protocol<Http2ProtocolHarness> protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame> headers;
    headers.header.type = static_cast<uint8_t>(qb::protocol::http2::FrameType::HEADERS);
    headers.header.flags = qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers({
        {":method", "GET"},
        {":scheme", "https"},
        {":authority", "example.test"},
        {":path", "/parent"}
    });
    protocol.on(std::move(headers));
    ASSERT_EQ(io.request_count, 1);

    qb::http::Request promised{qb::io::uri{"/asset"}};
    promised.method() = qb::http::method::GET;

    auto failure = protocol.send_push_promise(1, 2, std::move(promised));
    ASSERT_TRUE(failure.has_value());
    EXPECT_EQ(*failure, qb::protocol::http2::PushPromiseFailureReason::INVALID_PROMISED_REQUEST);
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

// Regression: a HEADERS frame with FLAG_PADDED|FLAG_PRIORITY whose declared
// length is exactly the prefix size (1 pad-length byte + 5 priority bytes) made
// the header-block size, computed as p_len - pad_length, underflow to SIZE_MAX
// and drive an out-of-bounds read in assign(). The framer must reject the frame
// as a FRAME_SIZE_ERROR. Drives raw wire bytes through the framer because the
// bug lives in handle_headers_frame_payload, not in on(HeadersFrame).
TEST(HTTP2ServerProtocol, PaddedPriorityHeadersLengthUnderflowIsRejected) {
    Http2ProtocolHarness io;
    qb::protocol::http2::ServerHttp2Protocol<Http2ProtocolHarness> protocol(io);

    auto push = [&](const void* p, std::size_t n) {
        std::memcpy(io.input.allocate_back(n), p, n);
    };

    // Connection preface.
    push(::HTTP2_CONNECTION_PREFACE.data(), ::HTTP2_CONNECTION_PREFACE.size());

    // Malicious HEADERS frame header: length = 6 (1 pad-length + 5 priority),
    // PADDED | PRIORITY, stream 1.
    qb::protocol::http2::FrameHeader fh{};
    fh.set_payload_length(6);
    fh.type  = static_cast<uint8_t>(qb::protocol::http2::FrameType::HEADERS);
    fh.flags = qb::protocol::http2::FLAG_PADDED | qb::protocol::http2::FLAG_PRIORITY;
    fh.set_stream_id(1);
    push(&fh, sizeof(fh));

    // Payload: pad_length = 1, then the 5 priority bytes; nothing left for the
    // declared padding byte or any header block — the malformed part.
    const std::uint8_t payload[6] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
    push(payload, sizeof(payload));

    std::size_t sz = 0;
    while ((sz = protocol.getMessageSize()) > 0) {
        protocol.onMessage(sz);
        io.input.free_front(sz);
        if (!protocol.ok()) {
            break;
        }
    }

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(),
              qb::protocol::http2::ErrorCode::FRAME_SIZE_ERROR);
    EXPECT_EQ(io.request_count, 0);
}

namespace {
struct ThrowingRequestHarness {
    using base_io_t = ThrowingRequestHarness;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;
    bool handler_invoked = false;
    int  stream_error_count = 0;
    int  goaway_count = 0;

    qb::allocator::pipe<char>& in() noexcept { return input; }
    qb::allocator::pipe<char>& out() noexcept { return output; }

    template <typename Frame>
    ThrowingRequestHarness& operator<<(const Frame& frame) {
        output.put(frame);
        return *this;
    }

    void on(qb::http::Request&&, uint32_t) {
        handler_invoked = true;
        throw std::runtime_error("request handler boom");
    }
    void on(const qb::protocol::http2::Http2StreamErrorEvent&) { ++stream_error_count; }
    void on(const qb::protocol::http2::Http2GoAwayEvent&) { ++goaway_count; }
};
} // namespace

// Regression: an HTTP/2 request handler runs synchronously from the noexcept
// frame-dispatch chain (on(HeadersFrame) -> dispatch_complete_request ->
// _io.on(request)). Before the dispatch-boundary try/catch, a throwing handler
// escaped that noexcept boundary and called std::terminate. The protocol must
// instead reset the offending stream and keep the connection alive.
TEST(HTTP2ServerProtocol, ThrowingRequestHandlerIsContainedAndConnectionSurvives) {
    ThrowingRequestHarness io;
    qb::protocol::http2::ServerHttp2Protocol<ThrowingRequestHarness> protocol(io);

    auto push = [&](const void* p, std::size_t n) {
        std::memcpy(io.input.allocate_back(n), p, n);
    };

    push(::HTTP2_CONNECTION_PREFACE.data(), ::HTTP2_CONNECTION_PREFACE.size());

    const auto encoded = encode_hpack_headers({
        {":method", "GET"},
        {":path", "/"},
        {":scheme", "https"},
        {":authority", "example.com"},
    });

    qb::protocol::http2::FrameHeader fh{};
    fh.set_payload_length(static_cast<uint32_t>(encoded.size()));
    fh.type  = static_cast<uint8_t>(qb::protocol::http2::FrameType::HEADERS);
    fh.flags = qb::protocol::http2::FLAG_END_STREAM | qb::protocol::http2::FLAG_END_HEADERS;
    fh.set_stream_id(1);
    push(&fh, sizeof(fh));
    push(encoded.data(), encoded.size());

    std::size_t sz = 0;
    while ((sz = protocol.getMessageSize()) > 0) {
        protocol.onMessage(sz);
        io.input.free_front(sz);
        if (!protocol.ok()) {
            break;
        }
    }

    // The handler was reached and threw; the dispatch-boundary catch reset the
    // stream instead of terminating, and the connection is still alive.
    EXPECT_TRUE(io.handler_invoked);
    EXPECT_TRUE(protocol.ok());
}

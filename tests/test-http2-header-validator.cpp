#include <gtest/gtest.h>

#include "../2/protocol/base.h"
#include "../2/protocol/client.h"

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

/**
 * @file qbm/http/tests/unit/http3/http3-validation.cpp
 * @brief Unit tier: pure RFC-9114 / RFC-7230 field-logic for the HTTP/3 detail layer.
 *
 * These tests exercise the @c qb::protocol::http3::detail field-validation and
 * field-block-assembly helpers (header ordering, pseudo-header rules,
 * content-length parsing, forbidden-header/trailer detection, request/response
 * header-block synthesis). They run entirely in-memory over @c header_block /
 * @c qb::http::Request / @c qb::http::Response objects — NO QUIC stack, NO event
 * loop, NO sockets — so they are deterministic and parallel-safe.
 *
 * They were extracted from the former monolithic @c test-http3-client.cpp, whose
 * @c Http3ProtocolValidationTest suite was welded into the same translation unit
 * as the QUIC+TLS loopback and external-tool tests. As their own TU they build
 * and run without paying the loopback cost. The @c QBM_HTTP_HAS_HTTP3 gate is
 * retained because the @c detail helpers are only declared in an HTTP/3 build.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <qbm/http/http.h>

#if defined(QBM_HTTP_HAS_HTTP3)

#include <optional>
#include <string>

namespace h3detail = qb::protocol::http3::detail;

// ---------------------------------------------------------------------------
// header_block ordering + required request pseudo-headers
// ---------------------------------------------------------------------------

TEST(Http3ProtocolValidationTest, AcceptsPseudoHeadersBeforeRegularHeaders) {
    qb::protocol::http3::detail::header_block block;
    block.add(":method", "GET");
    block.add(":scheme", "https");
    block.add(":authority", "example.test");
    block.add(":path", "/");
    block.add("x-test", "1");

    EXPECT_TRUE(qb::protocol::http3::detail::pseudo_headers_before_regular_headers(block));
}

TEST(Http3ProtocolValidationTest, RejectsPseudoHeadersAfterRegularHeaders) {
    qb::protocol::http3::detail::header_block block;
    block.add(":method", "GET");
    block.add(":scheme", "https");
    block.add("x-test", "1");
    block.add(":path", "/");

    EXPECT_FALSE(qb::protocol::http3::detail::pseudo_headers_before_regular_headers(block));
}

TEST(Http3ProtocolValidationTest, RequiresNonEmptyAuthorityAndPathForRequests) {
    std::optional<std::string> method    = "GET";
    std::optional<std::string> scheme    = "https";
    std::optional<std::string> authority = "example.test";
    std::optional<std::string> path      = "/";

    EXPECT_TRUE(qb::protocol::http3::detail::has_required_request_pseudo_headers(method, scheme, authority, path));

    authority = "";
    EXPECT_FALSE(qb::protocol::http3::detail::has_required_request_pseudo_headers(method, scheme, authority, path));

    authority = std::nullopt;
    EXPECT_FALSE(qb::protocol::http3::detail::has_required_request_pseudo_headers(method, scheme, authority, path));

    authority = "example.test";
    path      = "";
    EXPECT_FALSE(qb::protocol::http3::detail::has_required_request_pseudo_headers(method, scheme, authority, path));
}

// ---------------------------------------------------------------------------
// content-length parsing + declaration reconciliation
// ---------------------------------------------------------------------------

TEST(Http3ProtocolValidationTest, ParseContentLengthAcceptsWellFormedDecimals) {
    auto zero = h3detail::parse_content_length("0");
    ASSERT_TRUE(zero.has_value());
    EXPECT_EQ(*zero, 0u);

    auto big = h3detail::parse_content_length("12345");
    ASSERT_TRUE(big.has_value());
    EXPECT_EQ(*big, 12345u);
}

TEST(Http3ProtocolValidationTest, ParseContentLengthRejectsMalformedValues) {
    EXPECT_FALSE(h3detail::parse_content_length("").has_value());    // empty
    EXPECT_FALSE(h3detail::parse_content_length("12a").has_value()); // trailing junk
    EXPECT_FALSE(h3detail::parse_content_length(" 12").has_value()); // leading space
    EXPECT_FALSE(h3detail::parse_content_length("-1").has_value());  // signed
    // 2^64 = 18446744073709551616 overflows std::uint64_t -> nullopt.
    EXPECT_FALSE(h3detail::parse_content_length("18446744073709551616").has_value());
}

TEST(Http3ProtocolValidationTest, DeclaredContentLengthHandlesAbsentSingleAndConflicting) {
    {
        qb::http::Request req{qb::io::uri("https://h/")};
        auto              result = h3detail::declared_content_length(req);
        EXPECT_TRUE(result.ok);
        EXPECT_FALSE(result.value.has_value());
    }
    {
        qb::http::Request req{qb::io::uri("https://h/")};
        req.set_header("content-length", "5");
        auto result = h3detail::declared_content_length(req);
        EXPECT_TRUE(result.ok);
        ASSERT_TRUE(result.value.has_value());
        EXPECT_EQ(*result.value, 5u);
    }
    {
        qb::http::Request req{qb::io::uri("https://h/")};
        req.add_header("content-length", "5");
        req.add_header("content-length", "5");
        auto result = h3detail::declared_content_length(req);
        EXPECT_TRUE(result.ok);
        ASSERT_TRUE(result.value.has_value());
        EXPECT_EQ(*result.value, 5u);
    }
    {
        qb::http::Request req{qb::io::uri("https://h/")};
        req.add_header("content-length", "5");
        req.add_header("content-length", "6");
        auto result = h3detail::declared_content_length(req);
        EXPECT_FALSE(result.ok);
    }
    {
        qb::http::Response res;
        res.set_header("content-length", "12a");
        auto result = h3detail::declared_content_length(res);
        EXPECT_FALSE(result.ok);
    }
}

// ---------------------------------------------------------------------------
// header-field validation (RFC 7230 / RFC 9114)
// ---------------------------------------------------------------------------

TEST(Http3ProtocolValidationTest, IsValidHeaderFieldEnforcesRfc7230) {
    EXPECT_TRUE(h3detail::is_valid_header_field("x-test", "ok"));
    EXPECT_FALSE(h3detail::is_valid_header_field("", "ok"));                         // empty name
    EXPECT_FALSE(h3detail::is_valid_header_field("X-Test", "ok"));                   // uppercase name
    EXPECT_FALSE(h3detail::is_valid_header_field("x test", "ok"));                   // space in name
    EXPECT_FALSE(h3detail::is_valid_header_field("x-test", "a\rb"));                 // CR in value
    EXPECT_FALSE(h3detail::is_valid_header_field("x-test", "a\nb"));                 // LF in value
    EXPECT_FALSE(h3detail::is_valid_header_field("x-test", std::string("a\0b", 3))); // NUL
    EXPECT_TRUE(h3detail::is_valid_header_field("x-test", "a\tb"));                  // TAB allowed

    const std::string oversize_name(qb::http::protocol_limits::MAX_HEADER_NAME_LENGTH + 1, 'a');
    EXPECT_FALSE(h3detail::is_valid_header_field(oversize_name, "ok"));
    const std::string oversize_value(qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'v');
    EXPECT_FALSE(h3detail::is_valid_header_field("x-test", oversize_value));
}

TEST(Http3ProtocolValidationTest, IsValidIncomingHeaderFieldAllowsPseudoHeaders) {
    EXPECT_TRUE(h3detail::is_valid_incoming_header_field(":path", "/"));
    EXPECT_FALSE(h3detail::is_valid_incoming_header_field(":", "x"));     // bare colon
    EXPECT_FALSE(h3detail::is_valid_incoming_header_field(":Path", "/")); // uppercase after colon
}

TEST(Http3ProtocolValidationTest, IsForbiddenH3HeaderMatchesConnectionFields) {
    EXPECT_TRUE(h3detail::is_forbidden_h3_header("connection"));
    EXPECT_TRUE(h3detail::is_forbidden_h3_header("Connection")); // case-insensitive
    EXPECT_TRUE(h3detail::is_forbidden_h3_header("keep-alive"));
    EXPECT_TRUE(h3detail::is_forbidden_h3_header("transfer-encoding"));
    EXPECT_TRUE(h3detail::is_forbidden_h3_header("upgrade"));
    EXPECT_TRUE(h3detail::is_forbidden_h3_header("proxy-connection"));
    EXPECT_TRUE(h3detail::is_forbidden_h3_header("proxy-authenticate"));
    EXPECT_TRUE(h3detail::is_forbidden_h3_header("proxy-authorization"));
    EXPECT_FALSE(h3detail::is_forbidden_h3_header("content-type"));
}

TEST(Http3ProtocolValidationTest, IsForbiddenH3TrailerRejectsControlAndPseudoFields) {
    EXPECT_TRUE(h3detail::is_forbidden_h3_trailer(""));        // empty
    EXPECT_TRUE(h3detail::is_forbidden_h3_trailer(":status")); // pseudo-header
    EXPECT_TRUE(h3detail::is_forbidden_h3_trailer("content-length"));
    EXPECT_TRUE(h3detail::is_forbidden_h3_trailer("trailer"));
    EXPECT_FALSE(h3detail::is_forbidden_h3_trailer("x-trace"));
}

// ---------------------------------------------------------------------------
// request-target / authority / announced-trailer derivation
// ---------------------------------------------------------------------------

TEST(Http3ProtocolValidationTest, RequestTargetBuildsOriginForm) {
    EXPECT_EQ(h3detail::request_target(qb::io::uri("https://h/")), "/");
    EXPECT_EQ(h3detail::request_target(qb::io::uri("https://h/a/b?x=1")), "/a/b?x=1");
}

TEST(Http3ProtocolValidationTest, AuthorityIncludesPortWhenPresent) {
    // qb::io::uri populates the default scheme port (443 for https), so authority()
    // appends ":443" even when the URI omits an explicit port.
    EXPECT_EQ(h3detail::authority(qb::io::uri("https://h/")), "h:443");
    EXPECT_EQ(h3detail::authority(qb::io::uri("https://h:8443/")), "h:8443");
}

TEST(Http3ProtocolValidationTest, AnnouncedTrailersParsesTrailerHeaderList) {
    {
        qb::http::Request req{qb::io::uri("https://h/")};
        req.set_header("trailer", "x-a, x-b");
        auto trailers = h3detail::announced_trailers(req);
        ASSERT_EQ(trailers.size(), 2u);
        EXPECT_EQ(trailers[0], "x-a");
        EXPECT_EQ(trailers[1], "x-b");
        EXPECT_TRUE(h3detail::is_announced_trailer("X-A", trailers)); // case-insensitive
        EXPECT_TRUE(h3detail::is_announced_trailer("x-b", trailers));
        EXPECT_FALSE(h3detail::is_announced_trailer("x-c", trailers));
    }
    {
        qb::http::Request req{qb::io::uri("https://h/")};
        auto              trailers = h3detail::announced_trailers(req);
        EXPECT_TRUE(trailers.empty());
    }
}

// ---------------------------------------------------------------------------
// request/response header-block + trailer-block assembly
// ---------------------------------------------------------------------------

TEST(Http3ProtocolValidationTest, MakeRequestHeadersOrdersPseudoHeadersAndDropsHost) {
    qb::http::Request req{qb::http::method::GET, qb::io::uri("https://example.test/path?q=1")};
    req.set_header("host", "should-be-dropped");
    req.set_header("x-custom", "v");

    auto block = h3detail::make_request_headers(req);
    ASSERT_TRUE(block.has_value());
    ASSERT_GE(block->storage.size(), 4u);
    EXPECT_EQ(block->storage[0].first, ":method");
    EXPECT_EQ(block->storage[1].first, ":scheme");
    EXPECT_EQ(block->storage[2].first, ":authority");
    EXPECT_EQ(block->storage[3].first, ":path");
    EXPECT_TRUE(h3detail::pseudo_headers_before_regular_headers(*block));

    // host is folded into :authority and must not appear as a regular field.
    for (auto const &[name, value] : block->storage) {
        (void) value;
        EXPECT_NE(name, "host");
    }
    // :authority carries the default https port (443) populated by qb::io::uri.
    EXPECT_EQ(block->storage[2].second, "example.test:443");
    EXPECT_EQ(block->storage[3].second, "/path?q=1");
}

TEST(Http3ProtocolValidationTest, MakeRequestHeadersSynthesizesContentLengthForBody) {
    qb::http::Request req{qb::http::method::POST, qb::io::uri("https://example.test/echo")};
    req.body() = "payload";

    auto block = h3detail::make_request_headers(req);
    ASSERT_TRUE(block.has_value());
    bool found_content_length = false;
    for (auto const &[name, value] : block->storage) {
        if (name == "content-length") {
            found_content_length = true;
            EXPECT_EQ(value, std::to_string(std::string("payload").size()));
        }
    }
    EXPECT_TRUE(found_content_length);
}

TEST(Http3ProtocolValidationTest, MakeRequestHeadersRejectsContentLengthBodyMismatch) {
    qb::http::Request req{qb::http::method::POST, qb::io::uri("https://example.test/echo")};
    req.body() = "12345";
    req.set_header("content-length", "99");

    EXPECT_FALSE(h3detail::make_request_headers(req).has_value());
}

TEST(Http3ProtocolValidationTest, MakeRequestHeadersRejectsForbiddenHeader) {
    qb::http::Request req{qb::http::method::GET, qb::io::uri("https://example.test/")};
    req.set_header("connection", "keep-alive");

    EXPECT_FALSE(h3detail::make_request_headers(req).has_value());
}

TEST(Http3ProtocolValidationTest, MakeResponseHeadersPutsStatusFirst) {
    qb::http::Response res;
    res.status() = qb::http::status::OK;
    res.set_header("x-extra", "v");

    auto block = h3detail::make_response_headers(res);
    ASSERT_TRUE(block.has_value());
    ASSERT_GE(block->storage.size(), 1u);
    EXPECT_EQ(block->storage[0].first, ":status");
    EXPECT_EQ(block->storage[0].second, "200");
}

TEST(Http3ProtocolValidationTest, MakeResponseHeadersSynthesizesContentLengthForBody) {
    qb::http::Response res;
    res.status() = qb::http::status::OK;
    res.body()   = "hello";

    auto block = h3detail::make_response_headers(res);
    ASSERT_TRUE(block.has_value());
    bool found_content_length = false;
    for (auto const &[name, value] : block->storage) {
        if (name == "content-length") {
            found_content_length = true;
            EXPECT_EQ(value, std::to_string(std::string("hello").size()));
        }
    }
    EXPECT_TRUE(found_content_length);
}

TEST(Http3ProtocolValidationTest, MakeResponseHeadersRejectsForbiddenHeader) {
    qb::http::Response res;
    res.status() = qb::http::status::OK;
    res.set_header("transfer-encoding", "chunked");

    EXPECT_FALSE(h3detail::make_response_headers(res).has_value());
}

TEST(Http3ProtocolValidationTest, MakeTrailersHonorsAnnouncedTrailers) {
    {
        // No trailer header -> no trailer block.
        qb::http::Response res;
        res.status() = qb::http::status::OK;
        EXPECT_FALSE(h3detail::make_trailers(res).has_value());
    }
    {
        // Announced and present valid trailer -> non-empty block.
        qb::http::Response res;
        res.status() = qb::http::status::OK;
        res.set_header("trailer", "x-checksum");
        res.set_header("x-checksum", "abc123");
        auto block = h3detail::make_trailers(res);
        ASSERT_TRUE(block.has_value());
        EXPECT_FALSE(block->nva.empty());
        EXPECT_EQ(block->storage.front().first, "x-checksum");
        EXPECT_EQ(block->storage.front().second, "abc123");
    }
    {
        // Announcing a forbidden trailer name -> nullopt.
        qb::http::Response res;
        res.status() = qb::http::status::OK;
        res.set_header("trailer", "content-length");
        res.set_header("content-length", "5");
        EXPECT_FALSE(h3detail::make_trailers(res).has_value());
    }
}

TEST(Http3ProtocolValidationTest, ResponseBodyLengthMustMatchSkipsBodylessSemantics) {
    qb::http::Response ok;
    ok.status() = qb::http::status::OK;
    EXPECT_TRUE(h3detail::response_body_length_must_match(ok, qb::http::method::GET));
    EXPECT_FALSE(h3detail::response_body_length_must_match(ok, qb::http::method::HEAD));

    qb::http::Response no_content;
    no_content.status() = qb::http::status::NO_CONTENT; // 204
    EXPECT_FALSE(h3detail::response_body_length_must_match(no_content, qb::http::method::GET));

    qb::http::Response not_modified;
    not_modified.status() = qb::http::status::NOT_MODIFIED; // 304
    EXPECT_FALSE(h3detail::response_body_length_must_match(not_modified, qb::http::method::GET));
}

#endif // QBM_HTTP_HAS_HTTP3

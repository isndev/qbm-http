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

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace h3detail = qb::protocol::http3::detail;

namespace {
/// How many fields named @p name a field block carries.
std::size_t
field_count(h3detail::header_block const &block, std::string_view name) {
    return static_cast<std::size_t>(std::count_if(block.storage.begin(), block.storage.end(), [&](auto const &f) { return f.first == name; }));
}
} // namespace

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

// :authority is optional -- a `host` field may name the authority instead (RFC 9114 section 4.3.1, Huly QB-1195) --
// but never empty; :method, :scheme and :path are required and never empty.
TEST(Http3ProtocolValidationTest, RequiresMethodSchemePathAndNoEmptyAuthority) {
    std::optional<std::string> method    = "GET";
    std::optional<std::string> scheme    = "https";
    std::optional<std::string> authority = "example.test";
    std::optional<std::string> path      = "/";

    EXPECT_TRUE(qb::protocol::http3::detail::has_required_request_pseudo_headers(method, scheme, authority, path));

    authority = "";
    EXPECT_FALSE(qb::protocol::http3::detail::has_required_request_pseudo_headers(method, scheme, authority, path));

    authority = std::nullopt;
    EXPECT_TRUE(qb::protocol::http3::detail::has_required_request_pseudo_headers(method, scheme, authority, path))
        << "without :authority, the request's `host` field names its authority";

    for (auto *required : {&method, &scheme, &path}) {
        auto const kept = *required;
        *required       = std::nullopt;
        EXPECT_FALSE(qb::protocol::http3::detail::has_required_request_pseudo_headers(method, scheme, authority, path));
        *required = "";
        EXPECT_FALSE(qb::protocol::http3::detail::has_required_request_pseudo_headers(method, scheme, authority, path));
        *required = kept;
    }

    authority = "example.test";
    path      = "";
    EXPECT_FALSE(qb::protocol::http3::detail::has_required_request_pseudo_headers(method, scheme, authority, path));
}

// A request names one authority by its `host` fields (Huly QB-1195): at most one beside :authority, exactly one
// without it -- the fields over the request limits counted, the first of them among the kept ones. nghttp3 refuses a
// second `host` and a request with neither itself; this is qbm-http's own rule, nghttp3 being a system library.
TEST(Http3ProtocolValidationTest, ARequestNamesOneAuthorityByItsHostFields) {
    using qb::protocol::http3::detail::has_one_request_authority;
    EXPECT_TRUE(has_one_request_authority(true, 0, 0));
    EXPECT_TRUE(has_one_request_authority(true, 1, 0));
    EXPECT_TRUE(has_one_request_authority(true, 1, 1)) << "the one host over the limits is the kept one";
    EXPECT_FALSE(has_one_request_authority(true, 2, 0));
    EXPECT_FALSE(has_one_request_authority(true, 1, 2)) << "a second host over the limits, dropped, still counts";
    EXPECT_FALSE(has_one_request_authority(false, 0, 0)) << "neither :authority nor host";
    EXPECT_TRUE(has_one_request_authority(false, 1, 0));
    EXPECT_TRUE(has_one_request_authority(false, 1, 1));
    EXPECT_FALSE(has_one_request_authority(false, 2, 0));
    EXPECT_FALSE(has_one_request_authority(false, 2, 1));
    EXPECT_FALSE(has_one_request_authority(false, 1, 3));
    EXPECT_FALSE(has_one_request_authority(false, 0, 1)) << "no host kept: nothing to compose the URI from";
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

// A field value neither starts nor ends with SP or HTAB: RFC 9114 section 4.2 holds it to RFC 9110 section 5.5's
// field-content (Huly QB-1191: such a value was sent). Whitespace inside it is part of it; an empty value is one.
TEST(Http3ProtocolValidationTest, AFieldValueWithWhitespaceAtAnEndIsInvalid) {
    for (const char *value : {" a", "a ", "\ta", "a\t", " ", "\t", " a "}) {
        EXPECT_FALSE(h3detail::is_valid_header_field("x-test", value)) << "[" << value << "]";
        EXPECT_FALSE(h3detail::is_valid_incoming_header_field("x-test", value)) << "[" << value << "]";
    }
    for (const char *value : {"a b", "a\tb", "a \t b", "", "a"}) {
        EXPECT_TRUE(h3detail::is_valid_header_field("x-test", value)) << "[" << value << "]";
        EXPECT_TRUE(h3detail::is_valid_incoming_header_field("x-test", value)) << "[" << value << "]";
    }
    // A request leaves without it, as an HTTP/2 request does; a response, or a trailer section, is refused.
    qb::http::Request req{qb::http::method::GET, qb::io::uri("https://example.test/r")};
    req.set_header("x-edge", " a");
    req.set_header("x-kept", "1");
    const auto block = h3detail::make_request_headers(req);
    ASSERT_TRUE(block.has_value());
    EXPECT_EQ(field_count(*block, "x-edge"), 0u);
    EXPECT_EQ(field_count(*block, "x-kept"), 1u);
    qb::http::Response res;
    res.status() = qb::http::status::OK;
    res.set_header("x-edge", "a\t");
    EXPECT_FALSE(h3detail::make_response_headers(res).has_value());
    qb::http::Response trailed;
    trailed.status() = qb::http::status::OK;
    trailed.trailers().set_header("x-sum", " abc");
    const auto plan = h3detail::plan_trailers(trailed);
    ASSERT_TRUE(plan.has_value());
    EXPECT_FALSE(h3detail::make_trailer_block(*plan).has_value());
}

TEST(Http3ProtocolValidationTest, IsForbiddenH3HeaderMatchesConnectionFields) {
    EXPECT_TRUE(h3detail::is_forbidden_h3_header("connection"));
    EXPECT_TRUE(h3detail::is_forbidden_h3_header("Connection")); // case-insensitive
    EXPECT_TRUE(h3detail::is_forbidden_h3_header("keep-alive"));
    EXPECT_TRUE(h3detail::is_forbidden_h3_header("transfer-encoding"));
    EXPECT_TRUE(h3detail::is_forbidden_h3_header("upgrade"));
    EXPECT_TRUE(h3detail::is_forbidden_h3_header("proxy-connection"));
    EXPECT_FALSE(h3detail::is_forbidden_h3_header("content-type"));
    // The proxy authentication fields are no connection-specific fields (RFC 9114 section 4.2): a header section
    // carries them, as HTTP/2's does; a trailer section does not (Huly QB-1197).
    EXPECT_FALSE(h3detail::is_forbidden_h3_header("proxy-authenticate"));
    EXPECT_FALSE(h3detail::is_forbidden_h3_header("proxy-authorization"));
    EXPECT_FALSE(h3detail::is_forbidden_h3_header("Proxy-Authorization"));
    EXPECT_TRUE(h3detail::is_forbidden_h3_trailer("proxy-authenticate"));
    EXPECT_TRUE(h3detail::is_forbidden_h3_trailer("proxy-authorization"));
    // Compared in place, by length then without regard to case (Huly QB-1191: the name was copied and folded): every
    // case of each name, and a name of each length one octet off, or one octet longer or shorter.
    for (const char *name : {"UPGRADE", "Connection", "KEEP-ALIVE", "Proxy-Connection", "TRANSFER-ENCODING"}) {
        EXPECT_TRUE(h3detail::is_forbidden_h3_header(name)) << name;
    }
    for (const char *name :
         {"upgradx", "connectiox", "keep-alivx", "proxy-connectiox", "transfer-encodinx", "upgrades", "upgrad", "connections", "keep-alive ",
          "", "te"}) {
        EXPECT_FALSE(h3detail::is_forbidden_h3_header(name)) << name;
    }
}

// Empty, a pseudo-header, or a field of the one trailer list HTTP/1.1, HTTP/2 and HTTP/3 share
// (qb::http::detail::is_forbidden_trailer_field): `host` and `te` included, which HTTP/3 accepted in
// a trailer section while HTTP/1.1 and HTTP/2 refused them (Huly QB-1073).
TEST(Http3ProtocolValidationTest, IsForbiddenH3TrailerRejectsControlAndPseudoFields) {
    EXPECT_TRUE(h3detail::is_forbidden_h3_trailer(""));        // empty
    EXPECT_TRUE(h3detail::is_forbidden_h3_trailer(":status")); // pseudo-header
    for (const char *name :
         {"content-length", "transfer-encoding", "trailer", "host", "connection", "keep-alive", "proxy-connection", "te", "upgrade",
          "http2-settings", "proxy-authenticate", "proxy-authorization", "Host", "TE"}) {
        EXPECT_TRUE(h3detail::is_forbidden_h3_trailer(name)) << name;
    }
    EXPECT_FALSE(h3detail::is_forbidden_h3_trailer("x-trace"));
    EXPECT_FALSE(h3detail::is_forbidden_h3_trailer("server-timing"));
}

// ---------------------------------------------------------------------------
// request-target / authority / announced-trailer derivation
// ---------------------------------------------------------------------------

TEST(Http3ProtocolValidationTest, RequestTargetBuildsOriginForm) {
    EXPECT_EQ(h3detail::request_target(qb::io::uri("https://h/")), "/");
    EXPECT_EQ(h3detail::request_target(qb::io::uri("https://h/a/b?x=1")), "/a/b?x=1");
}

namespace {
// The :authority a request's header block carries.
std::string
sent_authority(const char *uri, const char *host_header = nullptr) {
    qb::http::Request req{qb::http::method::GET, qb::io::uri(uri)};
    if (host_header) {
        req.set_header("host", host_header); // a Host header does not repair :authority: it is folded away
    }
    const auto block = h3detail::make_request_headers(req);
    EXPECT_TRUE(block.has_value()) << uri;
    if (!block || block->storage.size() < 3u) {
        return "<no block>";
    }
    EXPECT_EQ(block->storage[2].first, ":authority");
    return block->storage[2].second;
}
} // namespace

// :authority is the authority every protocol sends (qb::http::origin::authority, Huly QB-1064): the
// port when it is not the scheme's default. qb::io::uri fills the default in (443 for https), and
// HTTP/3 sent it -- "h:443" where HTTP/1.1 sent `Host: h`.
TEST(Http3ProtocolValidationTest, AuthorityOmitsTheSchemesDefaultPort) {
    EXPECT_EQ(sent_authority("https://h/"), "h");
    EXPECT_EQ(sent_authority("https://h:443/"), "h");
    EXPECT_EQ(sent_authority("https://h:8443/"), "h:8443");
}

// An IP-literal host is written between brackets, the port after them (RFC 3986 section 3.2.2), and
// :authority carries exactly that (RFC 9114 section 4.3.1). qb::io::uri keeps the literal without its
// brackets in host() -- what a socket wants -- so the builder must restore them (Huly QB-572); a zone
// identifier stays local, never sent (RFC 9844 section 6, Huly QB-1064).
TEST(Http3ProtocolValidationTest, AuthorityBracketsAnIPv6Literal) {
    EXPECT_EQ(sent_authority("https://[::1]:8443/"), "[::1]:8443");
    EXPECT_EQ(sent_authority("https://[::1]/"), "[::1]");
    EXPECT_EQ(sent_authority("https://[2001:db8::7]:4433/p?q=1"), "[2001:db8::7]:4433");
    EXPECT_EQ(sent_authority("https://127.0.0.1:8443/"), "127.0.0.1:8443");
    EXPECT_EQ(sent_authority("https://[fe80::1%25eth0]:8443/"), "[fe80::1]:8443");
    EXPECT_EQ(sent_authority("https://[::1]:8443/path", "[::1]:8443"), "[::1]:8443");
}

// A message's trailer section, planned once (Huly QB-1073): none without a `trailer` header or
// trailers(); else the announced fields that leave the header section -- lowercased, a forbidden one
// left in it -- then trailers().
TEST(Http3ProtocolValidationTest, PlanTrailersReadsTheAnnouncementAndTheContainer) {
    {
        qb::http::Request req{qb::io::uri("https://h/")};
        EXPECT_FALSE(h3detail::plan_trailers(req).has_value());
    }
    {
        qb::http::Request req{qb::io::uri("https://h/")};
        req.set_header("trailer", "X-A, x-b, content-length");
        req.set_header("x-a", "1");
        const auto plan = h3detail::plan_trailers(req);
        ASSERT_TRUE(plan.has_value());
        ASSERT_EQ(plan->moved.size(), 2u) << "a forbidden field stays in the header section";
        EXPECT_EQ(plan->moved[0], "x-a");
        EXPECT_EQ(plan->moved[1], "x-b");
        ASSERT_EQ(plan->fields.size(), 1u) << "x-b is announced, not set";
        EXPECT_EQ(plan->fields[0].first, "x-a");
        EXPECT_TRUE(plan->announcement.empty()) << "the request announces itself";
    }
    {
        qb::http::Request req{qb::io::uri("https://h/")};
        req.trailers().set_header("Grpc-Status", "0");
        const auto plan = h3detail::plan_trailers(req);
        ASSERT_TRUE(plan.has_value());
        EXPECT_TRUE(plan->moved.empty());
        ASSERT_EQ(plan->fields.size(), 1u);
        EXPECT_EQ(plan->fields[0].first, "grpc-status");
        EXPECT_EQ(plan->announcement, "grpc-status");
        EXPECT_TRUE(plan->forbidden.empty());
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
    // :authority leaves the default https port out, as every protocol's authority does (Huly QB-1064).
    EXPECT_EQ(block->storage[2].second, "example.test");
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

// A request's content-length is the body's, as the HTTP/2 client writes it (Huly QB-1191): a declared one is left out --
// it was sent, and a request whose body contradicted it was refused, which HTTP/2 sent with the body's length.
TEST(Http3ProtocolValidationTest, MakeRequestHeadersWritesTheBodysContentLength) {
    for (const char *declared : {"99", "5", "abc", "0"}) {
        qb::http::Request req{qb::http::method::POST, qb::io::uri("https://example.test/echo")};
        req.body() = "12345";
        req.set_header("content-length", declared);
        const auto block = h3detail::make_request_headers(req);
        ASSERT_TRUE(block.has_value()) << declared;
        ASSERT_EQ(field_count(*block, "content-length"), 1u) << declared;
        const auto length =
            std::find_if(block->storage.begin(), block->storage.end(), [](const auto &f) { return f.first == "content-length"; });
        EXPECT_EQ(length->second, "5") << declared;
    }
    qb::http::Request empty{qb::http::method::POST, qb::io::uri("https://example.test/echo")};
    empty.set_header("content-length", "0");
    const auto block = h3detail::make_request_headers(empty);
    ASSERT_TRUE(block.has_value());
    EXPECT_EQ(field_count(*block, "content-length"), 0u) << "no body, no length: the stream ends with its header section";
}

// The regular fields a request sends are those the servers accept on receipt, by the HTTP/2 client's rule
// (qb::protocol::http2::HeaderValidator::is_sent_request_field, Huly QB-1191): a connection-specific field -- RFC 9114
// section 4.2's, and `http2-settings` --, a `te` other than the one value `trailers`, a pseudo-header name, a value
// HTTP/3 cannot carry are left out, whatever their case, and the request is built; it was refused whole -- a
// `Connection: keep-alive` copied from an HTTP/1.1 message failed the request HTTP/2 sent.
TEST(Http3ProtocolValidationTest, ARequestLeavesOutTheFieldsTheServerRefuses) {
    const std::vector<std::pair<std::string, std::string>> left_out = {
        {"Connection", "keep-alive"},
        {"Proxy-Connection", "keep-alive"},
        {"Keep-Alive", "timeout=5"},
        {"Transfer-Encoding", "chunked"},
        {"Upgrade", "h2c"},
        {"HTTP2-Settings", "AAMAAABkAAQAAP__"},
        {"TE", "gzip"},
        {"TE", "trailers, trailers"},
        {":protocol", "websocket"},
        {"x-bad", "a\rb"},
    };
    for (auto const &[name, value] : left_out) {
        qb::http::Request req{qb::http::method::GET, qb::io::uri("https://example.test/r")};
        req.set_header(name, value);
        req.set_header("X-Kept", "1");
        const auto block = h3detail::make_request_headers(req);
        ASSERT_TRUE(block.has_value()) << name << ": the request is sent";
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](char c) { return qb::http::utility::ascii_to_lower(c); });
        EXPECT_EQ(field_count(*block, lower), 0u) << name << " left the client";
        EXPECT_EQ(field_count(*block, "x-kept"), 1u) << "a field the server accepts leaves lowercase";
        EXPECT_TRUE(h3detail::pseudo_headers_before_regular_headers(*block));
    }

    // A field the `connection` header names is connection-specific with it (RFC 9110 section 7.6.1): left out, whatever
    // its case -- `te` excepted, judged by its value.
    qb::http::Request req{qb::http::method::GET, qb::io::uri("https://example.test/r")};
    req.add_header("Connection", "X-Hop, te");
    req.add_header("Connection", " x-other ,");
    req.set_header("X-Hop", "1");
    req.set_header("X-Other", "2");
    req.set_header("TE", "trailers");
    req.set_header("X-Kept", "3");
    const auto block = h3detail::make_request_headers(req);
    ASSERT_TRUE(block.has_value());
    EXPECT_EQ(field_count(*block, "x-hop"), 0u);
    EXPECT_EQ(field_count(*block, "x-other"), 0u);
    EXPECT_EQ(field_count(*block, "connection"), 0u);
    EXPECT_EQ(field_count(*block, "te"), 1u);
    EXPECT_EQ(field_count(*block, "x-kept"), 1u);

    // A field past HTTP/3's bounds still refuses the request: a peer's nghttp3 takes one past its own for a connection
    // error.
    qb::http::Request big{qb::http::method::GET, qb::io::uri("https://example.test/r")};
    big.set_header("x-big", std::string(qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'v'));
    EXPECT_FALSE(h3detail::make_request_headers(big).has_value());
    qb::http::Request long_name{qb::http::method::GET, qb::io::uri("https://example.test/r")};
    long_name.set_header(std::string(qb::http::protocol_limits::MAX_HEADER_NAME_LENGTH + 1, 'n'), "v");
    EXPECT_FALSE(h3detail::make_request_headers(long_name).has_value());
}

// `te` is a connection-specific field a request carries as `trailers` alone, in any case, and a response never (RFC
// 9114 section 4.2, Huly QB-1191): any other value used to be sent, and the peer's nghttp3 closed the connection. A
// request leaves without it, as an HTTP/2 one does; a response is refused.
TEST(Http3ProtocolValidationTest, ATeFieldIsSentAsTrailersInARequestOnly) {
    for (const char *value : {"trailers", "Trailers"}) {
        qb::http::Request req{qb::http::method::GET, qb::io::uri("https://example.test/")};
        req.set_header("TE", value);
        const auto block = h3detail::make_request_headers(req);
        ASSERT_TRUE(block.has_value()) << value;
        const auto te = std::find_if(block->storage.begin(), block->storage.end(), [](const auto &f) { return f.first == "te"; });
        ASSERT_NE(te, block->storage.end()) << value;
        EXPECT_EQ(te->second, value);
    }
    for (const char *value : {"gzip", "trailers, gzip", "trailers, trailers", ""}) {
        qb::http::Request req{qb::http::method::GET, qb::io::uri("https://example.test/")};
        req.set_header("te", value);
        const auto block = h3detail::make_request_headers(req);
        ASSERT_TRUE(block.has_value()) << "te: " << value;
        EXPECT_EQ(field_count(*block, "te"), 0u) << "te: " << value;
    }
    qb::http::Request two{qb::http::method::GET, qb::io::uri("https://example.test/")};
    two.add_header("te", "trailers");
    two.add_header("te", "gzip");
    const auto both = h3detail::make_request_headers(two);
    ASSERT_TRUE(both.has_value());
    EXPECT_EQ(field_count(*both, "te"), 1u) << "every value of the field is judged: `trailers` leaves, `gzip` does not";

    qb::http::Response res;
    res.status() = qb::http::status::OK;
    res.set_header("te", "trailers");
    EXPECT_FALSE(h3detail::make_response_headers(res).has_value()) << "a response carries no te";
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

// A response's `host` is sent, as HTTP/1.1 and HTTP/2 send it (Huly QB-1189): it is no connection-specific field (RFC
// 9114 section 4.2) and names no authority. It was dropped, as a request's is -- which stays.
TEST(Http3ProtocolValidationTest, MakeResponseHeadersSendsAHostField) {
    qb::http::Response res;
    res.status() = qb::http::status::OK;
    res.set_header("Host", "example.test");
    const auto block = h3detail::make_response_headers(res);
    ASSERT_TRUE(block.has_value());
    ASSERT_EQ(field_count(*block, "host"), 1u);
    const auto host = std::find_if(block->storage.begin(), block->storage.end(), [](const auto &f) { return f.first == "host"; });
    EXPECT_EQ(host->second, "example.test");
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

// The trailer block and the header block split a message the way HTTP/1.1 and HTTP/2 do (Huly
// QB-1073): an announced field leaves the header block for the trailer block, a forbidden one stays in
// the header block -- the response was refused -- and a forbidden field of trailers() refuses it.
TEST(Http3ProtocolValidationTest, MakeTrailerBlockHonorsTheTrailerSection) {
    const auto count = [](const h3detail::header_block &block, std::string_view name) {
        return std::count_if(block.storage.begin(), block.storage.end(), [&](const auto &f) { return f.first == name; });
    };
    {
        // Announced and present valid trailer -> in the trailer block, not in the header block.
        qb::http::Response res;
        res.status() = qb::http::status::OK;
        res.set_header("trailer", "x-checksum");
        res.set_header("x-checksum", "abc123");
        const auto plan = h3detail::plan_trailers(res);
        ASSERT_TRUE(plan.has_value());
        auto block = h3detail::make_trailer_block(*plan);
        ASSERT_TRUE(block.has_value());
        ASSERT_EQ(block->nva.size(), 1u);
        EXPECT_EQ(block->storage.front().first, "x-checksum");
        EXPECT_EQ(block->storage.front().second, "abc123");
        const auto headers = h3detail::make_response_headers(res, plan);
        ASSERT_TRUE(headers.has_value());
        EXPECT_EQ(count(*headers, "x-checksum"), 0);
        EXPECT_EQ(count(*headers, "trailer"), 1);
    }
    {
        // Announcing a forbidden trailer name: the field stays in the header block, no trailer field.
        qb::http::Response res;
        res.status() = qb::http::status::OK;
        res.set_header("trailer", "content-length");
        res.set_header("content-length", "5");
        res.body()      = "hello";
        const auto plan = h3detail::plan_trailers(res);
        ASSERT_TRUE(plan.has_value());
        EXPECT_TRUE(plan->fields.empty());
        const auto headers = h3detail::make_response_headers(res, plan);
        ASSERT_TRUE(headers.has_value());
        EXPECT_EQ(count(*headers, "content-length"), 1);
    }
    {
        // trailers() announced when the response announces nothing; a forbidden one refuses it.
        qb::http::Response res;
        res.status() = qb::http::status::OK;
        res.trailers().set_header("grpc-status", "0");
        const auto headers = h3detail::make_response_headers(res);
        ASSERT_TRUE(headers.has_value());
        ASSERT_EQ(count(*headers, "trailer"), 1);
        res.trailers().set_header("te", "trailers");
        EXPECT_FALSE(h3detail::make_response_headers(res).has_value());
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

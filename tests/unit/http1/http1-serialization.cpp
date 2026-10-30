/**
 * @file qbm/http/tests/unit/http1/http1-serialization.cpp
 * @brief Pure-logic unit tests for HTTP/1.x message serialization & header values.
 *
 * These cases need no event loop, no socket and no thread: they construct
 * `Request`/`Response`/`Multipart`/`ContentType` value types and serialize them
 * through a `qb::allocator::pipe<char>`, asserting the exact wire bytes and the
 * serializer's Content-Length / Transfer-Encoding / no-body-status validation
 * contract. Also covers `qb::http::host_header_value()` default-port elision and
 * IPv6 bracketing, and Content-Type / multipart parsing.
 *
 * Peeled out of the former `test-session-http.cpp` (the runtime loopback half
 * now lives in system/http1/http1-loopback.cpp).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <qb/system/allocator/pipe.h>

#include <qbm/http/http.h>

TEST(Http1Serialization, ContentTypeParsesTypeAndCharset) {
    auto res = qb::http::Request::ContentType("application/json;charset=utf-16");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-16");
    res = qb::http::Request::ContentType("   application/json   ;   charset    =   utf-16   ");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-16");
    res = qb::http::Request::ContentType("application/json;charset=\"utf-16\"");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-16");
    res = qb::http::Request::ContentType("application/json;charset=utf-16;");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-16");
    res = qb::http::Request::ContentType("application/json;charset=");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-8");
    res = qb::http::Request::ContentType("application/json;charlot=utf-16");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-8");
    res = qb::http::Request::ContentType("application/json;");
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-8");
    res = qb::http::Request::ContentType("");
    EXPECT_EQ(res.type(), "application/octet-stream");
    EXPECT_EQ(res.charset(), "utf-8");
}

TEST(Http1Serialization, ContentTypeParsesFromStringView) {
    auto res = qb::http::Request::ContentType(std::string_view{"application/json;charset=utf-16"});
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-16");
    res = qb::http::Request::ContentType(std::string_view{"   application/json   ;   charset    =   utf-16   "});
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-16");
    res = qb::http::Request::ContentType(std::string_view{"application/json;charset=\"utf-16\""});
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-16");
    res = qb::http::Request::ContentType(std::string_view{"application/json;charset=utf-16;"});
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-16");
    res = qb::http::Request::ContentType(std::string_view{"application/json;charset="});
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-8");
    res = qb::http::Request::ContentType(std::string_view{"application/json;charlot=utf-16"});
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-8");
    res = qb::http::Request::ContentType(std::string_view{"application/json;"});
    EXPECT_EQ(res.type(), "application/json");
    EXPECT_EQ(res.charset(), "utf-8");
    res = qb::http::Request::ContentType(std::string_view{""});
    EXPECT_EQ(res.type(), "application/octet-stream");
    EXPECT_EQ(res.charset(), "utf-8");
}

TEST(Http1Serialization, MultipartRoundTripsPartsAndDispositions) {
    qb::http::Multipart mp;

    auto &part1                            = mp.create_part();
    part1.headers()["Content-Disposition"] = {R"(form-data; name="company")"};
    part1.headers()["Content-Type"]        = {"text"};
    part1.body                             = "isndev";
    auto &part2                            = mp.create_part();
    part2.headers()["Content-Disposition"] = {R"(file; name="file"; filename="file1.txt")"};
    part2.headers()["Content-Type"]        = {"application/json"};
    part2.body                             = R"({"hello": "true"})";

    qb::http::Request req{HTTP_POST, {"https://isndev.test"}, {{"Content-Type", {"multipart/form-data"}}}, mp};
    req.body() = mp;

    auto mp2 = req.body().as<qb::http::Multipart>();
    EXPECT_EQ(mp2.parts()[0].header("Content-Type"), "text");
    EXPECT_EQ(mp2.parts()[0].body, "isndev");
    auto attrs = qb::http::parse_header_attributes(mp2.parts()[0].header("Content-Disposition"));
    EXPECT_TRUE(attrs.has("Form-Data"));
    EXPECT_EQ(attrs.at("name"), "company");

    EXPECT_EQ(mp2.parts()[1].header("Content-Type"), "application/json");
    EXPECT_EQ(mp2.parts()[1].body, R"({"hello": "true"})");
    attrs = qb::http::parse_header_attributes(mp2.parts()[1].header("Content-Disposition"));
    EXPECT_TRUE(attrs.has("File"));
    EXPECT_EQ(attrs.at("Name"), "file");
    EXPECT_EQ(attrs.at("Filename"), "file1.txt");
}

TEST(Http1Serialization, HostHeaderFormatsIpv6WithBrackets) {
    qb::io::uri uri{"http://[2001:db8::1]/resource"};
    EXPECT_EQ(qb::http::host_header_value(uri), "[2001:db8::1]");
}

TEST(Http1Serialization, HostHeaderFormatsIpv6WithPortAndBrackets) {
    qb::io::uri uri{"http://[2001:db8::1]:8080/resource"};
    EXPECT_EQ(qb::http::host_header_value(uri), "[2001:db8::1]:8080");
}

TEST(Http1Serialization, HostValueOmitsExplicitDefaultHttpPort) {
    const qb::io::uri u{"http://api.example.com:80/v1"};
    EXPECT_EQ(u.port(), "80");
    EXPECT_EQ(qb::http::host_header_value(u), "api.example.com");
}

TEST(Http1Serialization, HostValueOmitsExplicitDefaultHttpsPort) {
    const qb::io::uri u{"https://api.example.com:443/secure"};
    EXPECT_EQ(u.port(), "443");
    EXPECT_EQ(qb::http::host_header_value(u), "api.example.com");
}

TEST(Http1Serialization, HostValueOmitsHttpsDefaultPortOnIpv6) {
    const qb::io::uri u{"https://[2001:db8::1]:443/secure"};
    EXPECT_EQ(qb::http::host_header_value(u), "[2001:db8::1]");
}

// An IPv6 literal's zone identifier has local significance only and is never sent on the wire
// (RFC 9844 §6, RFC 6874 §4 before it): the Host value leaves it out, as every protocol's authority
// does (qb::http::origin::authority, Huly QB-1064). It was sent.
TEST(Http1Serialization, HostValueLeavesAnIpv6ZoneOut) {
    const qb::io::uri zoned{"http://[fe80::1%25eth0]:8080/p"};
    ASSERT_TRUE(zoned.is_valid());
    EXPECT_EQ(qb::http::host_header_value(zoned), "[fe80::1]:8080");
    const qb::io::uri zoned_default{"https://[fe80::1%25eth0]:443/p"};
    EXPECT_EQ(qb::http::host_header_value(zoned_default), "[fe80::1]");
}

TEST(Http1Serialization, HostValueRetainsNonDefaultPort) {
    const qb::io::uri u{"https://api.example.com:4443/secure"};
    EXPECT_EQ(qb::http::host_header_value(u), "api.example.com:4443");
}

TEST(Http1Serialization, HostValueDefaultPortsSchemeCaseInsensitive) {
    // Mixed-case schemes must still elide :80 / :443; value matches uri.host().
    const qb::io::uri a{"HTTP://host-ssl-test.example:80/p"};
    const qb::io::uri b{"HtTpS://host-ssl-test2.example:443/p"};
    EXPECT_EQ(a.port(), "80");
    EXPECT_EQ(b.port(), "443");
    EXPECT_EQ(qb::http::host_header_value(a), std::string(a.host()));
    EXPECT_EQ(qb::http::host_header_value(b), std::string(b.host()));
}

// A URI whose scheme has no registered default port leaves uri.port() empty, so
// host_header_value (qb::http::origin::authority) returns the bare host. "http"/"https"/"ws"
// all inject a default port, so a custom scheme is used to keep the port genuinely absent.
TEST(Http1Serialization, HostValueWithoutPortReturnsBareHost) {
    const qb::io::uri u{"custom-scheme://api.example.com/path"};
    EXPECT_TRUE(u.port().empty());
    EXPECT_EQ(qb::http::host_header_value(u), "api.example.com");
}

// A scheme that has the SAME length as "http" but differs in a character is not
// http: it has no default port, so the port is appended even though it is 80.
TEST(Http1Serialization, HostValueAppendsPortWhenSchemeLengthMatchesButDiffers) {
    // "ftp" is length 3 (vs "http" length 4) — pick a 4-char non-http scheme so
    // the length guard passes and the per-char compare runs to a mismatch.
    const qb::io::uri u{"htxp://api.example.com:80/path"};
    EXPECT_EQ(u.port(), "80");
    // Not recognised as the http default => :80 is retained.
    EXPECT_EQ(qb::http::host_header_value(u), "api.example.com:80");
}

TEST(Http1Serialization, RequestRejectsContentLengthMismatch) {
    qb::http::Request request{qb::http::method::POST, {"http://example.test/upload"}};
    request.set_header("Content-Length", "1");
    request.body() = "abc";

    qb::allocator::pipe<char> out;
    EXPECT_THROW(out << request, std::length_error);
    EXPECT_EQ(out.size(), 0u);
}

TEST(Http1Serialization, ResponseRejectsContentLengthMismatch) {
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("Content-Length", "1");
    response.body() = "abc";

    qb::allocator::pipe<char> out;
    EXPECT_THROW(out << response, std::length_error);
    EXPECT_EQ(out.size(), 0u);
}

TEST(Http1Serialization, RejectsContentLengthWithTransferEncoding) {
    qb::http::Request request{qb::http::method::POST, {"http://example.test/upload"}};
    request.set_header("Transfer-Encoding", "chunked");
    request.set_header("Content-Length", "3");
    request.body() = "abc";

    qb::allocator::pipe<char> out;
    EXPECT_THROW(out << request, std::length_error);
    EXPECT_EQ(out.size(), 0u);
}

TEST(Http1Serialization, RejectsUnsupportedTransferEncoding) {
    qb::http::Request request{qb::http::method::POST, {"http://example.test/upload"}};
    request.set_header("Transfer-Encoding", "gzip, chunked");
    request.body() = "abc";

    qb::allocator::pipe<char> out;
    EXPECT_THROW(out << request, std::length_error);
    EXPECT_EQ(out.size(), 0u);
}

TEST(Http1Serialization, RequestChunksPresentBody) {
    qb::http::Request request{qb::http::method::POST, {"http://example.test/upload"}};
    request.set_header("Transfer-Encoding", "chunked");
    request.body() = "abc";

    qb::allocator::pipe<char> out;
    ASSERT_NO_THROW(out << request);
    const std::string wire{out.begin(), out.size()};

    EXPECT_NE(wire.find("transfer-encoding: chunked\r\n"), std::string::npos);
    EXPECT_NE(wire.find("\r\n\r\n3\r\nabc\r\n0\r\n\r\n"), std::string::npos);
    EXPECT_EQ(wire.find("content-length:"), std::string::npos);
}

TEST(Http1Serialization, RequestOmitsUriFragment) {
    qb::http::Request request{qb::http::method::GET, {"http://example.test/search?q=qb#client-only"}};

    qb::allocator::pipe<char> out;
    ASSERT_NO_THROW(out << request);
    const std::string wire{out.begin(), out.size()};

    EXPECT_TRUE(wire.starts_with("GET /search?q=qb HTTP/1.1\r\n"));
    EXPECT_EQ(wire.find("#client-only"), std::string::npos);
}

TEST(Http1Serialization, RequestPreservesExplicitEmptyQueryAcrossValueOperations) {
    for (const std::string &path : {std::string{"/"}, std::string{"/target"}, std::string(160, 'x').insert(0, "/")}) {
        for (const std::string &fragment : {std::string{}, std::string{"#client-only"}}) {
            qb::io::uri retained;
            {
                qb::io::uri original{"http://example.test" + path + "?" + fragment};
                qb::io::uri copied{original};
                qb::io::uri moved{std::move(copied)};
                retained = std::move(moved);
            }
            qb::http::Request         request{qb::http::method::GET, retained};
            qb::allocator::pipe<char> out;
            ASSERT_NO_THROW(out << request);
            const std::string wire{out.begin(), out.size()};
            EXPECT_TRUE(wire.starts_with("GET " + path + "? HTTP/1.1\r\n")) << wire;
        }
    }
}

TEST(Http1Serialization, RequestKeepsAbsentQueryAndEncodedDelimitersDistinct) {
    for (const auto &[source, target] :
         {std::pair{"http://example.test/a", "/a"}, std::pair{"http://example.test/a#ignored?x", "/a"},
          std::pair{"http://example.test/a?q=%3F", "/a?q=%3F"}, std::pair{"http://example.test/a%3Fb", "/a%3Fb"}}) {
        qb::http::Request         request{qb::http::method::GET, {source}};
        qb::allocator::pipe<char> out;
        ASSERT_NO_THROW(out << request);
        const std::string wire{out.begin(), out.size()};
        EXPECT_TRUE(wire.starts_with(std::string{"GET "} + target + " HTTP/1.1\r\n")) << wire;
    }
}

TEST(Http1Serialization, ResponseChunksPresentBody) {
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("Transfer-Encoding", "chunked");
    response.body() = "abc";

    qb::allocator::pipe<char> out;
    ASSERT_NO_THROW(out << response);
    const std::string wire{out.begin(), out.size()};

    EXPECT_NE(wire.find("transfer-encoding: chunked\r\n"), std::string::npos);
    EXPECT_NE(wire.find("\r\n\r\n3\r\nabc\r\n0\r\n\r\n"), std::string::npos);
    EXPECT_EQ(wire.find("content-length:"), std::string::npos);
}

TEST(Http1Serialization, ResponseRejectsBodyForNoBodyStatus) {
    qb::http::Response response;
    response.status() = qb::http::status::NO_CONTENT;
    response.body()   = "abc";

    qb::allocator::pipe<char> out;
    EXPECT_THROW(out << response, std::length_error);
    EXPECT_EQ(out.size(), 0u);
}

TEST(Http1Serialization, ResponseAllowsHeadStyleContentLength) {
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("Content-Length", "4");

    qb::allocator::pipe<char> out;
    ASSERT_NO_THROW(out << response);
    const std::string wire{out.begin(), out.size()};

    EXPECT_NE(wire.find("content-length: 4\r\n"), std::string::npos);
    EXPECT_TRUE(wire.ends_with("\r\n\r\n"));
}

TEST(Http1Serialization, ResponseRejectsNonZeroContentLengthForNoBodyStatus) {
    qb::http::Response response;
    response.status() = qb::http::status::NO_CONTENT;
    response.set_header("Content-Length", "4");

    qb::allocator::pipe<char> out;
    EXPECT_THROW(out << response, std::length_error);
    EXPECT_EQ(out.size(), 0u);
}

TEST(Http1Serialization, ResponseAllowsNotModifiedContentLength) {
    qb::http::Response response;
    response.status() = qb::http::status::NOT_MODIFIED;
    response.set_header("Content-Length", "4");

    qb::allocator::pipe<char> out;
    ASSERT_NO_THROW(out << response);
    const std::string wire{out.begin(), out.size()};

    EXPECT_NE(wire.find("HTTP/1.1 304 "), std::string::npos);
    EXPECT_NE(wire.find("content-length: 4\r\n"), std::string::npos);
    EXPECT_TRUE(wire.ends_with("\r\n\r\n"));
}

TEST(Http1Serialization, ResponseRejectsTransferEncodingForNoBodyStatus) {
    qb::http::Response response;
    response.status() = qb::http::status::NOT_MODIFIED;
    response.set_header("Transfer-Encoding", "chunked");

    qb::allocator::pipe<char> out;
    EXPECT_THROW(out << response, std::length_error);
    EXPECT_EQ(out.size(), 0u);
}

// RFC 9112 §7.1: a chunked body ends with the last-chunk "0\r\n\r\n", even when it
// carries no data. The serializers wrote data chunk and terminator only in the
// non-empty branch, so an empty chunked message ended at the header section and the
// peer waited for a body that never came (Huly QB-493). Response also omitted its
// Content-Length: 0 fallback there, so nothing delimited the message at all.
TEST(Http1Serialization, RequestTerminatesAnEmptyChunkedBody) {
    qb::http::Request request{qb::http::method::POST, {"http://example.test/upload"}};
    request.set_header("Transfer-Encoding", "chunked");

    qb::allocator::pipe<char> out;
    ASSERT_NO_THROW(out << request);
    const std::string wire{out.begin(), out.size()};

    EXPECT_TRUE(wire.starts_with("POST /upload HTTP/1.1\r\n")) << wire;
    EXPECT_TRUE(wire.ends_with("\r\n\r\n0\r\n\r\n")) << "an empty chunked body still needs its last-chunk: " << wire;
    EXPECT_EQ(wire.find("content-length"), std::string::npos) << wire;
}

TEST(Http1Serialization, ResponseTerminatesAnEmptyChunkedBody) {
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("Transfer-Encoding", "chunked");

    qb::allocator::pipe<char> out;
    ASSERT_NO_THROW(out << response);
    const std::string wire{out.begin(), out.size()};

    EXPECT_TRUE(wire.starts_with("HTTP/1.1 200 ")) << wire;
    EXPECT_TRUE(wire.ends_with("\r\n\r\n0\r\n\r\n")) << "an empty chunked body still needs its last-chunk: " << wire;
    EXPECT_EQ(wire.find("content-length"), std::string::npos) << wire;
}

// `MessageHead{msg}` writes a message's start line and header section and nothing after them:
// no body, and no last-chunk either. The response to a HEAD request keeps the framing headers
// of the content a GET would have carried (RFC 9110 §9.3.2, RFC 9112 §6.1) — the Response does
// not know the method it answers, so the HTTP/1.1 session states the suppression explicitly; and
// a body streamed by hand needs its head on its own, since serializing the message writes a
// COMPLETE one (an empty chunked body is its last-chunk alone, QB-493).
TEST(Http1Serialization, MessageHeadEndsAtItsHeaderSection) {
    {
        qb::http::Response response;
        response.status() = qb::http::status::OK;
        response.set_header("Transfer-Encoding", "chunked");
        response.body() = "ignored: the content a GET would carry";

        qb::allocator::pipe<char> out;
        ASSERT_NO_THROW(out << qb::http::MessageHead{response});
        const std::string wire{out.begin(), out.size()};

        EXPECT_TRUE(wire.starts_with("HTTP/1.1 200 ")) << wire;
        EXPECT_NE(wire.find("transfer-encoding: chunked\r\n"), std::string::npos) << wire;
        EXPECT_EQ(wire.find("\r\n\r\n"), wire.size() - 4) << "nothing may follow the header section: " << wire;
        EXPECT_EQ(wire.find("ignored"), std::string::npos) << wire;
    }
    {
        qb::http::Response response;
        response.status() = qb::http::status::OK;
        response.set_header("Content-Length", "37");

        qb::allocator::pipe<char> out;
        ASSERT_NO_THROW(out << qb::http::MessageHead{response});
        const std::string wire{out.begin(), out.size()};

        EXPECT_NE(wire.find("content-length: 37\r\n"), std::string::npos) << wire;
        EXPECT_EQ(wire.find("\r\n\r\n"), wire.size() - 4) << wire;
    }
    {
        // A request head: what a hand-streamed chunked upload writes before its chunks. A declared
        // Content-Length is not checked against the (ignored) body.
        qb::http::Request chunked{qb::http::method::POST, {"http://example.test/upload?part=1"}};
        chunked.set_header("Transfer-Encoding", "chunked");
        qb::http::Request sized{qb::http::method::PUT, {"http://example.test/blob"}};
        sized.set_header("Content-Length", "4096");

        for (auto const *request : {&chunked, &sized}) {
            qb::allocator::pipe<char> out;
            ASSERT_NO_THROW(out << qb::http::MessageHead{*request});
            const std::string wire{out.begin(), out.size()};
            EXPECT_EQ(wire.find("\r\n\r\n"), wire.size() - 4) << wire;
        }
        qb::allocator::pipe<char> out;
        out << qb::http::MessageHead{chunked};
        EXPECT_TRUE(std::string(out.begin(), out.size()).starts_with("POST /upload?part=1 HTTP/1.1\r\n"));
    }
    {
        // The validation is the full serializer's: a no-body status still refuses TE, and a
        // request-target still refuses a raw SP.
        qb::http::Response response;
        response.status() = qb::http::status::NOT_MODIFIED;
        response.set_header("Transfer-Encoding", "chunked");
        qb::allocator::pipe<char> out;
        EXPECT_THROW(out << qb::http::MessageHead{response}, std::length_error);
        EXPECT_EQ(out.size(), 0u);

        qb::http::Request request{qb::http::method::GET, {"http://example.test/q?a=1 b"}};
        EXPECT_THROW(out << qb::http::MessageHead{request}, std::length_error);
        EXPECT_EQ(out.size(), 0u);
    }
}

// RFC 9112 §3.2: the request-target is the request line's middle token, so a byte
// that ends or breaks that line — SP, HTAB, CR, LF, NUL, any other control, DEL —
// cannot be carried raw. qb::io::uri keeps every query byte up to '#' (a generic URI
// parser), and the serializer copied that raw query into the request line after a
// length check only, emitting a malformed request (Huly QB-494). Percent-encoded
// forms are text and keep their bytes, as does every printable delimiter.
TEST(Http1Serialization, RequestRejectsBytesARequestTargetCannotCarry) {
    struct Case {
        const char *name;
        std::string query;
    };
    const Case cases[] = {
        {"SP", "a=1 b"},
        {"HTAB", "a=1\tb"},
        {"CR", "a=1\rb"},
        {"LF", "a=1\nb"},
        {"CRLF + forged header", "a=1\r\nX-Injected: yes"},
        {"NUL", std::string("a=1\0b", 5)},
        {"other control", "a=1\x01"
                          "b"},
        {"DEL", "a=1\x7f"
                "b"},
    };
    for (auto const &c : cases) {
        const qb::io::uri target{"http://example.test/search?" + c.query};
        ASSERT_EQ(target.encoded_queries(), c.query) << c.name << ": the premise is a URI that keeps the raw byte";

        qb::http::Request         request{qb::http::method::GET, target};
        qb::allocator::pipe<char> out;
        EXPECT_THROW(out << request, std::length_error) << "serialized a request-target with a raw " << c.name;
        EXPECT_EQ(out.size(), 0u) << c.name << ": nothing may be emitted before the refusal";
    }

    // Controls: encoded forms and printable punctuation keep their exact bytes.
    for (const std::string query : {"a=%20%09%0D%0A%00%7F", "a=1&b=2;c=/x?y:z@w!$'()*+,~-._", "q=%E2%82%AC&raw=\xE2\x82\xAC"}) {
        const qb::io::uri         target{"http://example.test/search?" + query};
        qb::http::Request         request{qb::http::method::GET, target};
        qb::allocator::pipe<char> out;
        ASSERT_NO_THROW(out << request) << query;
        const std::string wire{out.begin(), out.size()};
        EXPECT_TRUE(wire.starts_with("GET /search?" + query + " HTTP/1.1\r\n")) << wire;
    }

    // The check walks the query sixteen bytes at a time (eight where SSE2 is not the baseline, a
    // byte loop under eight) and re-reads the LAST block overlapped instead of looping over a tail:
    // every length up to 40 with the bad byte at every position, and every all-good length, so no
    // position falls between two blocks or past the last one.
    const auto refused = [](const std::string &query) {
        const qb::io::uri target{"http://example.test/s?" + query};
        EXPECT_EQ(target.encoded_queries(), query);
        qb::http::Request         request{qb::http::method::GET, target};
        qb::allocator::pipe<char> out;
        try {
            out << request;
        } catch (const std::length_error &) {
            return out.size() == 0u;
        }
        return false;
    };
    for (std::size_t n = 1; n <= 40; ++n) {
        for (std::size_t i = 0; i < n; ++i) {
            std::string query(n, 'q');
            query[i] = (i % 2) ? ' ' : '\x7f';
            EXPECT_TRUE(refused(query)) << "n=" << n << ", the bad byte at " << i << " slipped through";
        }
        const std::string good(n, (n % 2) ? '~' : '!'); // 0x7E and 0x21: the two edges of what may travel
        EXPECT_FALSE(refused(good)) << "n=" << n << ": an all-printable query was refused";
    }
    // The four edges of the byte classes, inside the overlapped last block of a 33-byte query.
    for (const auto &[byte, bad] :
         {std::pair{'\x20', true}, std::pair{'\x21', false}, std::pair{'\x7e', false}, std::pair{'\x7f', true}, std::pair{'\x80', false}}) {
        std::string query(33, 'q');
        query[20] = byte;
        EXPECT_EQ(refused(query), bad) << "byte 0x" << std::hex << (static_cast<unsigned>(byte) & 0xffu);
    }
}

// RFC 9112 §4: status-line = HTTP-version SP status-code SP [ reason-phrase ]. The phrase is
// advisory -- a client SHOULD ignore it -- but people and tools read it, and what belongs there
// is the IANA HTTP Status Code Registry's text (RFC 9110 §15), not the enum identifier llhttp's
// status map spells: `400 BAD_REQUEST`, `101 SWITCHING_PROTOCOLS` (Huly QB-1062). A code no
// table knows keeps a phrase the grammar admits.
TEST(Http1Serialization, StatusLineCarriesTheRegisteredReasonPhrase) {
    struct Case {
        qb::http::Status status;
        const char      *line;
    };
    const Case cases[] = {
        {qb::http::status::OK, "HTTP/1.1 200 OK\r\n"},
        {qb::http::status::SWITCHING_PROTOCOLS, "HTTP/1.1 101 Switching Protocols\r\n"},
        {qb::http::status::NO_CONTENT, "HTTP/1.1 204 No Content\r\n"},
        {qb::http::status::BAD_REQUEST, "HTTP/1.1 400 Bad Request\r\n"},
        {qb::http::status::NOT_FOUND, "HTTP/1.1 404 Not Found\r\n"},
        {qb::http::status::PAYLOAD_TOO_LARGE, "HTTP/1.1 413 Content Too Large\r\n"},
        {qb::http::status::UNPROCESSABLE_ENTITY, "HTTP/1.1 422 Unprocessable Content\r\n"},
        {qb::http::status::INTERNAL_SERVER_ERROR, "HTTP/1.1 500 Internal Server Error\r\n"},
        {qb::http::status::HTTP_VERSION_NOT_SUPPORTED, "HTTP/1.1 505 HTTP Version Not Supported\r\n"},
        {qb::http::Status{209}, "HTTP/1.1 209 Unknown Status\r\n"},
    };
    for (auto const &c : cases) {
        qb::http::Response response;
        response.status() = c.status;
        qb::allocator::pipe<char> out;
        ASSERT_NO_THROW(out << response) << c.line;
        const std::string wire{out.begin(), out.size()};
        EXPECT_TRUE(wire.starts_with(c.line)) << "expected " << c.line << "got " << wire;
    }
}

// Header names go on the wire in lower case, whatever case they were set in. Field names are
// case-insensitive (RFC 9110 §5.1); Headers keys each field by its folded name, which is the
// one lookup uses, the one HTTP/2 and HTTP/3 require (RFC 9113 §8.2.1, RFC 9114 §4.2), and the
// one HTTP/1.1 writes. Values keep their bytes. The contract Huly QB-1062 asked to settle: kept
// and documented, not a defect.
TEST(Http1Serialization, HeaderNamesAreWrittenInLowerCase) {
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("X-Request-ID", "AbC-123");
    response.add_header("Set-Cookie", "Session=XyZ");
    response.body() = "ok";
    qb::allocator::pipe<char> out;
    ASSERT_NO_THROW(out << response);
    const std::string wire{out.begin(), out.size()};
    EXPECT_NE(wire.find("\r\nx-request-id: AbC-123\r\n"), std::string::npos) << wire;
    EXPECT_NE(wire.find("\r\nset-cookie: Session=XyZ\r\n"), std::string::npos) << wire;
    EXPECT_EQ(wire.find("X-Request-ID"), std::string::npos) << wire;

    qb::http::Request request{qb::http::method::POST, {"http://example.test/a"}};
    request.set_header("Content-Type", "Text/Plain");
    request.body() = "x";
    qb::allocator::pipe<char> req_out;
    ASSERT_NO_THROW(req_out << request);
    const std::string req_wire{req_out.begin(), req_out.size()};
    EXPECT_NE(req_wire.find("\r\ncontent-type: Text/Plain\r\n"), std::string::npos) << req_wire;
    EXPECT_EQ(req_wire.find("Content-Type"), std::string::npos) << req_wire;
}

// A refused serialization takes back what IT wrote and nothing else: the pipe a session writes into
// already holds the responses (or requests) queued before this one, and a refusal used to clear()
// them all -- a pipelined response lost because the next one was invalid (Huly QB-1066). The
// refusals cover the request-target, the framing and the header section, for a whole message and
// for a MessageHead.
TEST(Http1Serialization, ARefusalKeepsTheOutputQueuedBeforeIt) {
    qb::http::Response queued;
    queued.status() = qb::http::status::OK;
    queued.body()   = "first";
    qb::allocator::pipe<char> reference;
    reference << queued;
    const std::string before{reference.begin(), reference.size()};

    const auto expect_kept = [&](auto const &message, const char *what) {
        qb::allocator::pipe<char> out;
        out << queued;
        EXPECT_THROW(out << message, std::length_error) << what;
        EXPECT_EQ(std::string(out.begin(), out.size()), before) << what << ": the queued response must survive the refusal";
        // And the pipe stays usable: the next message lands right after the queued one.
        out << queued;
        EXPECT_EQ(std::string(out.begin(), out.size()), before + before) << what;
    };

    expect_kept(qb::http::Request{qb::http::method::GET, {"http://example.test/q?a=1 b"}}, "raw SP in the query");

    qb::http::Response no_body;
    no_body.status() = qb::http::status::NO_CONTENT;
    no_body.body()   = "forbidden";
    expect_kept(no_body, "a body on 204");

    qb::http::Response injected;
    injected.status() = qb::http::status::OK;
    injected.set_header("X-Note", "a\r\nX-Injected: 1");
    expect_kept(injected, "CR LF inside a response header value");
    expect_kept(qb::http::MessageHead{injected}, "CR LF inside a response head");

    qb::http::Request injected_request{qb::http::method::GET, {"http://example.test/"}};
    injected_request.set_header("X-Note", "a\r\nX-Injected: 1");
    expect_kept(injected_request, "CR LF inside a request header value");
}

// RFC 9112 §3.2.1: "If the target URI's path component is empty, the client MUST send "/" as the
// path within the origin-form of request-target." qb::io::uri's parser already gives an
// authority-only URI the path "/", but a default-constructed Request keeps a never-parsed URI whose
// path is empty, and an invalid URI leaves the path empty too: the request line read
// `GET  HTTP/1.1`, a request-target of nothing (Huly QB-1066). An empty path is sent as "/"; a URI
// that failed to parse is refused, as a request the serializer cannot write -- sending it to "/"
// instead would address a resource nobody named.
TEST(Http1Serialization, AnEmptyPathIsSentAsSlash) {
    struct Case {
        const char *uri;
        const char *line;
    };
    const Case cases[] = {
        {"http://example.test", "GET / HTTP/1.1\r\n"},
        {"http://example.test?a=1", "GET /?a=1 HTTP/1.1\r\n"},
        {"http://example.test/x", "GET /x HTTP/1.1\r\n"},
    };
    for (auto const &c : cases) {
        const qb::io::uri         target{c.uri};
        qb::http::Request         request{qb::http::method::GET, target};
        qb::allocator::pipe<char> out;
        ASSERT_NO_THROW(out << request) << c.uri;
        const std::string wire{out.begin(), out.size()};
        EXPECT_TRUE(wire.starts_with(c.line)) << c.uri << " -> " << wire;
    }

    qb::http::Request defaulted;
    defaulted.method() = qb::http::method::GET;
    ASSERT_TRUE(defaulted.uri().path().empty()) << "the premise: a default Request's URI has no path";
    qb::allocator::pipe<char> out;
    ASSERT_NO_THROW(out << defaulted);
    const std::string wire{out.begin(), out.size()};
    EXPECT_TRUE(wire.starts_with("GET / HTTP/1.1\r\n")) << wire;

    qb::http::Request invalid{qb::http::method::GET, qb::io::uri{"http://exa mple.test/x"}};
    ASSERT_FALSE(invalid.uri().is_valid()) << "the premise: a URI that failed to parse";
    qb::allocator::pipe<char> refused;
    refused << "queued";
    EXPECT_THROW(refused << invalid, std::length_error);
    EXPECT_EQ(std::string(refused.begin(), refused.size()), "queued");
}

// A default-constructed Request has no method (Method::UNINITIALIZED), and the serializer named the
// method through llhttp's http_method_name(), whose switch ends in `default: abort()`: serializing
// `qb::http::Request{}` -- or any method value llhttp does not map -- killed the process instead of
// refusing the message like every other request it cannot write (Huly QB-1066). Run in a child, so
// the old abort is a failed expectation rather than a dead test binary.
TEST(Http1Serialization, ARequestWithoutAMethodIsRefusedNotAborted) {
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    EXPECT_EXIT(
        {
            qb::http::Request         request;
            qb::allocator::pipe<char> out;
            out << "queued";
            try {
                out << request;
            } catch (const std::length_error &) {
                std::_Exit(std::string(out.begin(), out.size()) == "queued" ? 0 : 2);
            }
            std::_Exit(3);
        },
        ::testing::ExitedWithCode(0), "");

    // A mapped method keeps its exact token, M-SEARCH's hyphen included.
    qb::http::Request         search{qb::http::method::MSEARCH, {"http://example.test/"}};
    qb::allocator::pipe<char> out;
    ASSERT_NO_THROW(out << search);
    EXPECT_TRUE(std::string(out.begin(), out.size()).starts_with("M-SEARCH / HTTP/1.1\r\n"));
}

// The fields a chunked message's `Trailer` header announces travel in its trailer section, after
// the last chunk, and not in its header section -- the contract HTTP/2 and HTTP/3 send by (Huly
// QB-1058, QB-1061; RFC 9112 §7.1.2). The serializer wrote every field in the header section and
// ended the body with a bare `0\r\n\r\n` (Huly QB-1067). A field a trailer section must not carry
// stays in the header section even when announced; an announced field the message does not set is
// simply absent; a message framed by Content-Length has no trailer section, so nothing moves.
TEST(Http1Serialization, AnnouncedTrailerFieldsTravelAfterTheLastChunk) {
    const auto head_and_tail = [](const std::string &wire) {
        const auto end = wire.find("\r\n\r\n");
        return std::pair{wire.substr(0, end + 2), wire.substr(end + 4)};
    };

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("Transfer-Encoding", "chunked");
    response.set_header("Trailer", "X-Checksum, Server-Timing, Connection, X-Unset");
    response.set_header("X-Checksum", "abc");
    response.add_header("Server-Timing", "db;dur=53");
    response.add_header("Server-Timing", "app;dur=47");
    response.set_header("Connection", "keep-alive");
    response.body() = "hello";
    qb::allocator::pipe<char> out;
    ASSERT_NO_THROW(out << response);
    const auto [head, tail] = head_and_tail(std::string(out.begin(), out.size()));

    EXPECT_EQ(head.find("x-checksum:"), std::string::npos) << head;
    EXPECT_EQ(head.find("server-timing:"), std::string::npos) << head;
    EXPECT_NE(head.find("\r\nconnection: keep-alive\r\n"), std::string::npos) << "a field trailers must not carry stays in the head";
    EXPECT_NE(head.find("\r\ntrailer: X-Checksum, Server-Timing, Connection, X-Unset\r\n"), std::string::npos) << head;
    // The trailer section, in the announced order; every value of a multi-value field.
    EXPECT_EQ(tail, "5\r\nhello\r\n0\r\nx-checksum: abc\r\nserver-timing: db;dur=53\r\nserver-timing: app;dur=47\r\n\r\n");

    // A request alike; its empty chunked body still ends with the trailer section.
    qb::http::Request request{qb::http::method::POST, {"http://example.test/up"}};
    request.set_header("Transfer-Encoding", "chunked");
    request.set_header("Trailer", "X-Checksum");
    request.set_header("X-Checksum", "abc");
    qb::allocator::pipe<char> req_out;
    ASSERT_NO_THROW(req_out << request);
    const auto [req_head, req_tail] = head_and_tail(std::string(req_out.begin(), req_out.size()));
    EXPECT_EQ(req_head.find("x-checksum:"), std::string::npos) << req_head;
    EXPECT_EQ(req_tail, "0\r\nx-checksum: abc\r\n\r\n");

    // Content-Length framing has no trailer section: the announced field stays in the head.
    qb::http::Response sized;
    sized.status() = qb::http::status::OK;
    sized.set_header("Trailer", "X-Checksum");
    sized.set_header("X-Checksum", "abc");
    sized.body() = "hello";
    qb::allocator::pipe<char> sized_out;
    ASSERT_NO_THROW(sized_out << sized);
    EXPECT_NE(std::string(sized_out.begin(), sized_out.size()).find("\r\nx-checksum: abc\r\n"), std::string::npos);

    // A MessageHead writes no trailer section of its own, so it keeps every field in the head: the
    // caller streaming the chunks writes the end.
    qb::allocator::pipe<char> head_only;
    ASSERT_NO_THROW(head_only << qb::http::MessageHead{response});
    EXPECT_NE(std::string(head_only.begin(), head_only.size()).find("\r\nx-checksum: abc\r\n"), std::string::npos);
}

// A message's trailers() travel in its trailer section, after the last chunk of a chunked message,
// after the fields its `Trailer` header announces; the head gains a `trailer` field naming them when
// the message announces nothing itself (RFC 9110 §6.6.2). HTTP/1.1 has no trailer section in any
// other framing: a message framed by Content-Length, or a MessageHead, writes no trailers() (Huly
// QB-1073).
TEST(Http1Serialization, TrailersContainerTravelsAfterTheLastChunkOfAChunkedMessage) {
    const auto head_and_tail = [](const std::string &wire) {
        const auto end = wire.find("\r\n\r\n");
        return std::pair{wire.substr(0, end + 2), wire.substr(end + 4)};
    };

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("Transfer-Encoding", "chunked");
    response.trailers().set_header("Server-Timing", "db;dur=53");
    response.body() = "hello";
    qb::allocator::pipe<char> out;
    ASSERT_NO_THROW(out << response);
    {
        const auto [head, tail] = head_and_tail(std::string(out.begin(), out.size()));
        EXPECT_NE(head.find("\r\ntrailer: server-timing\r\n"), std::string::npos) << "the announcement the message did not write: " << head;
        EXPECT_EQ(head.find("server-timing:"), std::string::npos) << head;
        EXPECT_EQ(tail, "5\r\nhello\r\n0\r\nserver-timing: db;dur=53\r\n\r\n");
    }

    // Announced header fields first, then trailers(); the message's own announcement is kept as is.
    qb::http::Request request{qb::http::method::POST, {"http://example.test/up"}};
    request.set_header("Transfer-Encoding", "chunked");
    request.set_header("Trailer", "X-Checksum, X-Late");
    request.set_header("X-Checksum", "abc");
    request.trailers().set_header("X-Late", "z");
    qb::allocator::pipe<char> req_out;
    ASSERT_NO_THROW(req_out << request);
    {
        const auto [head, tail] = head_and_tail(std::string(req_out.begin(), req_out.size()));
        EXPECT_NE(head.find("\r\ntrailer: X-Checksum, X-Late\r\n"), std::string::npos) << head;
        EXPECT_EQ(head.find("\r\ntrailer:", head.find("\r\ntrailer:") + 1), std::string::npos) << "one announcement: " << head;
        EXPECT_EQ(tail, "0\r\nx-checksum: abc\r\nx-late: z\r\n\r\n");
    }

    // Content-Length framing has no trailer section: trailers() is written nowhere.
    qb::http::Response sized;
    sized.status() = qb::http::status::OK;
    sized.trailers().set_header("Server-Timing", "db;dur=53");
    sized.body() = "hello";
    qb::allocator::pipe<char> sized_out;
    ASSERT_NO_THROW(sized_out << sized);
    EXPECT_EQ(std::string(sized_out.begin(), sized_out.size()).find("server-timing"), std::string::npos);

    // Nor does a MessageHead: the caller streaming the chunks writes the end.
    qb::allocator::pipe<char> head_only;
    ASSERT_NO_THROW(head_only << qb::http::MessageHead{response});
    EXPECT_EQ(std::string(head_only.begin(), head_only.size()).find("server-timing"), std::string::npos);

    // A message with a trailer section is written whole out of line, its start line included: the
    // same start line as the inline serializer writes for the same message without one.
    const auto first_line = [](const auto &message) {
        qb::allocator::pipe<char> wire;
        wire << message;
        const std::string text(wire.begin(), wire.size());
        return text.substr(0, text.find("\r\n"));
    };
    qb::http::Request queried{qb::http::method::PUT, {"http://example.test/a/b?x=1&y=two"}};
    queried.major_version = 1;
    queried.minor_version = 0;
    queried.set_header("Transfer-Encoding", "chunked");
    qb::http::Request queried_trailed = queried;
    queried_trailed.trailers().set_header("X-Sum", "1");
    EXPECT_EQ(first_line(queried_trailed), first_line(queried));
    EXPECT_EQ(first_line(queried_trailed), "PUT /a/b?x=1&y=two HTTP/1.0");
    qb::http::Response not_found;
    not_found.status() = qb::http::status::NOT_FOUND;
    not_found.set_header("Transfer-Encoding", "chunked");
    qb::http::Response not_found_trailed = not_found;
    not_found_trailed.trailers().set_header("X-Sum", "1");
    EXPECT_EQ(first_line(not_found_trailed), first_line(not_found));
    EXPECT_EQ(first_line(not_found_trailed), "HTTP/1.1 404 Not Found");
}

// A field of trailers() a trailer section must not carry, or one no header could carry, refuses
// the message before anything is written: what the pipe held before is kept (Huly QB-1066, QB-1073).
TEST(Http1Serialization, ATrailerFieldThatCannotTravelRefusesTheMessage) {
    const auto refused = [](auto &&message) {
        qb::allocator::pipe<char> out;
        out << "queued";
        try {
            out << message;
        } catch (const std::length_error &) {
            return std::string(out.begin(), out.size()) == "queued";
        }
        return false;
    };
    for (const std::string name : {"Content-Length", "Transfer-Encoding", "Trailer", "Host", "TE", "Connection", "Proxy-Authorization"}) {
        qb::http::Response response;
        response.set_header("Transfer-Encoding", "chunked");
        response.body() = "hello";
        response.trailers().set_header(name, "5");
        EXPECT_TRUE(refused(response)) << name;

        qb::http::Request request{qb::http::method::POST, {"http://example.test/up"}};
        request.set_header("Transfer-Encoding", "chunked");
        request.trailers().set_header(name, "5");
        EXPECT_TRUE(refused(request)) << name;
    }
    qb::http::Response invalid;
    invalid.set_header("Transfer-Encoding", "chunked");
    invalid.trailers().set_header("X-Bad", "a\r\nInjected: 1");
    EXPECT_TRUE(refused(invalid)) << "a CR LF in a trailer value";
}

// An HTTP/1.x message head carries the version its connection speaks (RFC 9112 §2.3): HTTP/1.0 for a message set to
// 1.0 on purpose, HTTP/1.1 for any other -- a message received over HTTP/2 or HTTP/3 (2.0, 3.0) and forwarded, or one
// whose version is no HTTP/1.x at all. The request line and the status line wrote `HTTP/2.0` and `HTTP/3.0`, which a
// qbm-http server answers 505 and no HTTP/1.1 client parses. The whole message and its MessageHead alike.
TEST(Http1Serialization, AMessageHeadCarriesTheVersionOfItsConnection) {
    struct Case {
        std::uint16_t    major, minor;
        std::string_view sent;
    };
    const auto wire = [](auto const &message) {
        qb::allocator::pipe<char> out;
        out << message;
        return std::string(out.begin(), out.size());
    };
    for (auto const &c :
         {Case{1, 1, "HTTP/1.1"}, Case{1, 0, "HTTP/1.0"}, Case{2, 0, "HTTP/1.1"}, Case{3, 0, "HTTP/1.1"}, Case{0, 9, "HTTP/1.1"}}) {
        qb::http::Request request{qb::http::method::GET, {"http://example.test/x"}};
        request.major_version          = c.major;
        request.minor_version          = c.minor;
        const std::string request_line = "GET /x " + std::string{c.sent} + "\r\n";
        EXPECT_TRUE(wire(request).starts_with(request_line)) << c.major << "." << c.minor << ": " << wire(request);
        EXPECT_TRUE(wire(qb::http::MessageHead{request}).starts_with(request_line)) << c.major << "." << c.minor;

        qb::http::Response response;
        response.major_version        = c.major;
        response.minor_version        = c.minor;
        const std::string status_line = std::string{c.sent} + " 200 OK\r\n";
        EXPECT_TRUE(wire(response).starts_with(status_line)) << c.major << "." << c.minor << ": " << wire(response);
        EXPECT_TRUE(wire(qb::http::MessageHead{response}).starts_with(status_line)) << c.major << "." << c.minor;
    }
}

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
#include <stdexcept>
#include <string>

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
// host_header_value returns the bare host via the empty-port early return
// (http.cpp:48-50). "http"/"https"/"ws" all inject a default port, so a custom
// scheme is used to keep the port genuinely absent.
TEST(Http1Serialization, HostValueWithoutPortReturnsBareHost) {
    const qb::io::uri u{"custom-scheme://api.example.com/path"};
    EXPECT_TRUE(u.port().empty());
    EXPECT_EQ(qb::http::host_header_value(u), "api.example.com");
}

// A scheme that has the SAME length as "http" but differs in a character makes
// scheme_eq_ignore_case take the char-mismatch branch (http.cpp:30-33 return
// false), so the non-default port is appended even though it is 80.
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

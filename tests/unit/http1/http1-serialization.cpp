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

#include "../http.h"

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

    qb::http::Request req{HTTP_POST, {"https://isndev.test"},
                          {{"Content-Type", {"multipart/form-data"}}}, mp};
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

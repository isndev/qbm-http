/**
 * @file qbm/http/tests/unit/message/message-types.cpp
 * @brief Unit tests for the core HTTP value types: Method, Status, Request,
 *        Response (types.h / request.h / response.h) and origin helpers (origin.cpp).
 *
 * These types are exercised constantly by the higher-level suites, but their own
 * accessor surface — string parsing, conversions, comparison operators, the
 * fluent `with_*` builders, case-insensitive header lookup, content-type parsing,
 * and the same-origin computation — is mostly assumed rather than asserted. This
 * file pins the observable contracts directly:
 *
 *   - Method: case-insensitive name → value, the "M-SEARCH"/"DELETE" aliases, the
 *     UNINITIALIZED placeholder (the guarded path that would otherwise abort in
 *     vendored llhttp), and the conversion / comparison operators.
 *   - Status: default 200, int/enum construction, code()/str()/string conversion,
 *     std::to_string, and comparisons.
 *   - Request/Response: default state, the fluent `with_*` chain, header set/get
 *     case-insensitivity, content-type parse, query accessors, and reset().
 *   - origin::{scheme_eq,host_eq,effective_port,effective_port_number,same}.
 *
 * Pure logic: no socket, no event loop.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <sstream>
#include <string>
#include <string_view>

#include <qb/io/uri.h>

#include "../origin.h"
#include "../request.h"
#include "../response.h"
#include "../types.h"

using qb::http::Method;
using qb::http::Request;
using qb::http::Response;
using qb::http::Status;

namespace {

// ===========================================================================
// Method
// ===========================================================================

TEST(MethodTest, DefaultIsUninitialized) {
    Method m;
    EXPECT_EQ(m, Method::UNINITIALIZED);
    // The guarded name lookup returns a readable placeholder rather than aborting
    // (vendored llhttp's http_method_name() would abort() on this value).
    EXPECT_EQ(std::string_view(m), "UNINITIALIZED");
    EXPECT_EQ(std::string(m), "UNINITIALIZED");
}

TEST(MethodTest, ParseFromStringCaseInsensitive) {
    EXPECT_EQ(Method("get"), Method::GET);
    EXPECT_EQ(Method("GET"), Method::GET);
    EXPECT_EQ(Method("GeT"), Method::GET);
    EXPECT_EQ(Method("post"), Method::POST);
    EXPECT_EQ(Method("DELETE"), Method::DEL);
    EXPECT_EQ(Method("M-SEARCH"), Method::MSEARCH);
}

TEST(MethodTest, ParseUnknownNameStaysUninitialized) {
    Method m("FLERBLE");
    EXPECT_EQ(m, Method::UNINITIALIZED);
    EXPECT_EQ(std::string_view(m), "UNINITIALIZED");
}

TEST(MethodTest, NameConversionForKnownMethods) {
    EXPECT_EQ(std::string(Method(Method::GET)), "GET");
    EXPECT_EQ(std::string(Method(Method::POST)), "POST");
    // The DELETE verb is exposed both as DEL and DELETE_METHOD aliases.
    EXPECT_EQ(Method::DEL, Method::DELETE_METHOD);
    EXPECT_EQ(std::string(Method(Method::DEL)), "DELETE");
    EXPECT_EQ(std::string(Method(Method::PATCH)), "PATCH");
}

TEST(MethodTest, ComparisonOperators) {
    Method g = Method::GET;
    EXPECT_TRUE(g == Method::GET);
    EXPECT_TRUE(g != Method::POST);
    EXPECT_TRUE(g == HTTP_GET); // against raw ::http_method
    EXPECT_TRUE(g != HTTP_POST);
    EXPECT_EQ(g, Method(HTTP_GET));

    // operator< gives a strict weak ordering keyed on the underlying value.
    EXPECT_TRUE((Method::DEL < Method::GET) || (Method::GET < Method::DEL));
    EXPECT_FALSE(Method::GET < Method::GET);
}

TEST(MethodTest, StdToStringAndStreaming) {
    EXPECT_EQ(std::to_string(Method(Method::PUT)), "PUT");

    std::ostringstream os;
    os << Method(Method::HEAD);
    EXPECT_EQ(os.str(), "HEAD");
}

// ===========================================================================
// Status
// ===========================================================================

TEST(StatusTest, DefaultIsOk) {
    Status s;
    EXPECT_EQ(s, Status::OK);
    EXPECT_EQ(s.code(), 200);
}

TEST(StatusTest, ConstructFromIntAndEnum) {
    Status from_int(404);
    EXPECT_EQ(from_int, Status::NOT_FOUND);
    EXPECT_EQ(from_int.code(), 404);

    Status from_enum(Status::CREATED);
    EXPECT_EQ(from_enum.code(), 201);
    EXPECT_EQ(from_enum, 201); // operator==(int)
}

TEST(StatusTest, ReasonPhraseConversions) {
    Status ok(Status::OK);
    EXPECT_EQ(ok.str(), "OK");
    EXPECT_EQ(std::string(ok), "OK");
    EXPECT_EQ(std::string_view(ok), "OK");

    // str() / the string conversions return the enum identifier, not the HTTP reason
    // phrase — "OK" matches both, but a multi-word status reveals the actual form.
    Status nf(Status::NOT_FOUND);
    EXPECT_EQ(nf.str(), "NOT_FOUND");
    EXPECT_EQ(std::to_string(nf), "NOT_FOUND");
}

TEST(StatusTest, UnmappedCodeYieldsUnknownStatusInsteadOfAborting) {
    // llhttp's http_status_name() calls abort() on any code absent from its sparse map;
    // 209-213 are gaps (208 ALREADY_REPORTED jumps straight to 214). Status stringification
    // must NOT delegate to it, or a peer response / an app setting such a code would crash
    // the whole process the moment the status is serialized or written to an access log.
    for (int code : {209, 210, 211, 212, 213}) {
        Status s(code);
        EXPECT_EQ(s.code(), code) << code;
        EXPECT_EQ(std::string(s), "Unknown Status") << code;
        EXPECT_EQ(std::string_view(s), std::string_view("Unknown Status")) << code;
        EXPECT_EQ(std::to_string(s), "Unknown Status") << code;
    }
    // Mapped codes keep their previous (byte-identical) reason token.
    EXPECT_EQ(std::to_string(Status(200)), "OK");
    EXPECT_EQ(std::to_string(Status(404)), "NOT_FOUND");
}

TEST(StatusTest, ComparisonOperators) {
    Status ok(Status::OK);
    EXPECT_TRUE(ok == Status::OK);
    EXPECT_TRUE(ok != Status::NOT_FOUND);
    EXPECT_TRUE(ok == 200);
    EXPECT_TRUE(ok != 404);
    EXPECT_TRUE(Status::OK < Status::NOT_FOUND); // 200 < 404
}

TEST(StatusTest, AssignmentOperators) {
    Status s;
    s = Status::ACCEPTED;
    EXPECT_EQ(s.code(), 202);
    s = 500;
    EXPECT_EQ(s, Status::INTERNAL_SERVER_ERROR);
}

// ===========================================================================
// Request
// ===========================================================================

TEST(RequestTest, DefaultStateIsUninitializedMethod) {
    Request req;
    EXPECT_EQ(req.method(), Method::UNINITIALIZED);
    EXPECT_TRUE(req.body().empty());
    EXPECT_EQ(req.major_version, 1);
    EXPECT_EQ(req.minor_version, 1);
}

TEST(RequestTest, FluentBuildersChain) {
    Request req;
    req.with_method(Method::POST).with_uri(qb::io::uri("/api/items?page=2")).with_header("X-Trace", "abc").with_body(std::string("payload"));

    EXPECT_EQ(req.method(), Method::POST);
    EXPECT_EQ(req.uri().path(), "/api/items");
    EXPECT_EQ(req.header("X-Trace"), "abc");
    EXPECT_EQ(req.body().as<std::string_view>(), "payload");
    EXPECT_EQ(req.query("page"), "2");
}

TEST(RequestTest, HeaderLookupIsCaseInsensitive) {
    Request req;
    req.set_header("Content-Type", std::string("application/json; charset=utf-8"));

    EXPECT_TRUE(req.has_header("content-type"));
    EXPECT_TRUE(req.has_header("CONTENT-TYPE"));
    EXPECT_EQ(req.header("content-type"), "application/json; charset=utf-8");
    // The cached ContentType helper is refreshed by set_header.
    EXPECT_EQ(req.content_type().type(), "application/json");
    EXPECT_EQ(req.content_type().charset(), "utf-8");
}

TEST(RequestTest, HeaderOrFallbackAndMissing) {
    Request req;
    EXPECT_TRUE(req.header("X-Absent").empty()); // by-reference miss → static empty
    EXPECT_EQ(req.header_or("X-Absent", "fallback"), "fallback");

    req.set_header("X-Present", std::string("v"));
    EXPECT_EQ(req.header_or("X-Present", "fallback"), "v");
}

TEST(RequestTest, MultiValueQueryAccess) {
    Request req;
    req.uri() = qb::io::uri("/search?tag=a&tag=b&tag=c");
    EXPECT_EQ(req.query("tag", 0), "a");
    EXPECT_EQ(req.query("tag", 1), "b");
    EXPECT_EQ(req.query("tag", 2), "c");
    EXPECT_TRUE(req.query("tag", 9).empty()); // out-of-range index → static empty
    EXPECT_EQ(req.query_or("missing", "none"), "none");
}

TEST(RequestTest, ResetRestoresDefaults) {
    Request req;
    req.with_method(Method::PUT).with_uri(qb::io::uri("/x")).with_header("H", "v").with_body(std::string("b"));
    req.reset();

    EXPECT_EQ(req.method(), Method::GET); // reset() sets GET (documented)
    EXPECT_TRUE(req.body().empty());
    EXPECT_FALSE(req.has_header("H"));
}

// ===========================================================================
// Response
// ===========================================================================

TEST(ResponseTest, DefaultStatusIsOk) {
    Response res;
    EXPECT_EQ(res.status(), Status::OK);
    EXPECT_TRUE(res.body().empty());
}

TEST(ResponseTest, FluentBuildersChain) {
    Response res;
    res.with_status(Status::CREATED).with_header("Location", "/items/9").with_body(std::string("{}"));

    EXPECT_EQ(res.status(), Status::CREATED);
    EXPECT_EQ(res.header("Location"), "/items/9");
    EXPECT_EQ(res.body().as<std::string_view>(), "{}");
}

TEST(ResponseTest, StatusConstructorOverload) {
    Response res(Status::NOT_FOUND);
    EXPECT_EQ(res.status(), Status::NOT_FOUND);
    EXPECT_EQ(res.status().code(), 404);
}

TEST(ResponseTest, ContentTypeRoundTrips) {
    Response res;
    res.set_content_type("text/plain; charset=iso-8859-1");
    EXPECT_EQ(res.content_type().type(), "text/plain");
    EXPECT_EQ(res.content_type().charset(), "iso-8859-1");
    EXPECT_EQ(res.header("Content-Type"), "text/plain; charset=iso-8859-1");
}

TEST(ResponseTest, ResetRestoresOkAndClearsBody) {
    Response res;
    res.with_status(Status::BAD_REQUEST).with_header("H", "v").with_body(std::string("oops"));
    res.reset();

    EXPECT_EQ(res.status(), Status::OK);
    EXPECT_TRUE(res.body().empty());
    EXPECT_FALSE(res.has_header("H"));
}

// ===========================================================================
// origin helpers
// ===========================================================================

TEST(OriginTest, SchemeAndHostEqualityCaseInsensitive) {
    using namespace qb::http::origin;
    EXPECT_TRUE(scheme_eq("http", "HTTP"));
    EXPECT_TRUE(scheme_eq("https", "https"));
    EXPECT_FALSE(scheme_eq("http", "https"));
    EXPECT_FALSE(scheme_eq("http", "ftp"));

    EXPECT_TRUE(host_eq("Example.COM", "example.com"));
    EXPECT_FALSE(host_eq("a.com", "b.com"));
    EXPECT_FALSE(host_eq("example.com", "example.com.")); // length differs
}

TEST(OriginTest, EffectivePortDefaultsByScheme) {
    using namespace qb::http::origin;
    EXPECT_EQ(effective_port(qb::io::uri("http://example.com/")), "80");
    EXPECT_EQ(effective_port(qb::io::uri("https://example.com/")), "443");
    EXPECT_EQ(effective_port(qb::io::uri("http://example.com:8080/")), "8080");
    // A scheme the URI parser has no default port for, with no explicit port,
    // yields no effective port. ("xyzzy" is not in qb::io::uri's default-port
    // table — unlike ftp/ssh/etc., which the parser fills in.)
    EXPECT_TRUE(effective_port(qb::io::uri("xyzzy://example.com/")).empty());
}

TEST(OriginTest, EffectivePortNumberParsesAndValidates) {
    using namespace qb::http::origin;
    auto p = effective_port_number(qb::io::uri("https://example.com/"));
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(*p, 443u);

    auto explicit_p = effective_port_number(qb::io::uri("http://example.com:1234/"));
    ASSERT_TRUE(explicit_p.has_value());
    EXPECT_EQ(*explicit_p, 1234u);

    // No effective port for a scheme without a known default and no explicit port.
    EXPECT_FALSE(effective_port_number(qb::io::uri("xyzzy://example.com/")).has_value());
}

TEST(OriginTest, SameOriginRequiresSchemeHostPort) {
    using namespace qb::http::origin;
    EXPECT_TRUE(same(qb::io::uri("http://example.com/a"), qb::io::uri("http://example.com/b")));
    // Default vs explicit port that resolve to the same number are same-origin.
    EXPECT_TRUE(same(qb::io::uri("https://example.com/"), qb::io::uri("https://example.com:443/")));
    EXPECT_TRUE(same(qb::io::uri("http://EXAMPLE.com/"), qb::io::uri("http://example.com/"))); // host case-insensitive

    // Differing scheme, host, or port breaks same-origin.
    EXPECT_FALSE(same(qb::io::uri("http://example.com/"), qb::io::uri("https://example.com/")));
    EXPECT_FALSE(same(qb::io::uri("http://a.com/"), qb::io::uri("http://b.com/")));
    EXPECT_FALSE(same(qb::io::uri("http://example.com:80/"), qb::io::uri("http://example.com:8080/")));
}

} // namespace

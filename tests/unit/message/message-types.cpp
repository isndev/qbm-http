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

#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include <qb/io/uri.h>

#include <qbm/http/origin.h>
#include <qbm/http/request.h>
#include <qbm/http/response.h>
#include <qbm/http/types.h>

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

    // str() / the string conversions return the reason phrase their documentation names
    // ("Not Found"), the text the HTTP/1.1 status line carries -- not the enum identifier
    // llhttp's status map spells, which they returned until Huly QB-1062. "OK" is both; a
    // multi-word status tells them apart.
    Status nf(Status::NOT_FOUND);
    EXPECT_EQ(nf.str(), "Not Found");
    EXPECT_EQ(std::string(nf), "Not Found");
    EXPECT_EQ(std::to_string(nf), "Not Found");
    std::ostringstream os;
    os << nf;
    EXPECT_EQ(os.str(), "Not Found");
}

// Every code of the IANA HTTP Status Code Registry that llhttp's status map holds carries
// the registry's text (RFC 9110 §15 names: 413 Content Too Large, 422 Unprocessable
// Content). 306 and 418 are "(Unused)" in the registry, so they keep the phrase of the
// document that defined them, as the codes llhttp maps beyond the registry do.
TEST(StatusTest, RegisteredCodesCarryTheRegistryText) {
    const std::pair<int, std::string_view> registry[] = {
        {100, "Continue"},
        {101, "Switching Protocols"},
        {102, "Processing"},
        {103, "Early Hints"},
        {200, "OK"},
        {201, "Created"},
        {202, "Accepted"},
        {203, "Non-Authoritative Information"},
        {204, "No Content"},
        {205, "Reset Content"},
        {206, "Partial Content"},
        {207, "Multi-Status"},
        {208, "Already Reported"},
        {226, "IM Used"},
        {300, "Multiple Choices"},
        {301, "Moved Permanently"},
        {302, "Found"},
        {303, "See Other"},
        {304, "Not Modified"},
        {305, "Use Proxy"},
        {307, "Temporary Redirect"},
        {308, "Permanent Redirect"},
        {400, "Bad Request"},
        {401, "Unauthorized"},
        {402, "Payment Required"},
        {403, "Forbidden"},
        {404, "Not Found"},
        {405, "Method Not Allowed"},
        {406, "Not Acceptable"},
        {407, "Proxy Authentication Required"},
        {408, "Request Timeout"},
        {409, "Conflict"},
        {410, "Gone"},
        {411, "Length Required"},
        {412, "Precondition Failed"},
        {413, "Content Too Large"},
        {414, "URI Too Long"},
        {415, "Unsupported Media Type"},
        {416, "Range Not Satisfiable"},
        {417, "Expectation Failed"},
        {421, "Misdirected Request"},
        {422, "Unprocessable Content"},
        {423, "Locked"},
        {424, "Failed Dependency"},
        {425, "Too Early"},
        {426, "Upgrade Required"},
        {428, "Precondition Required"},
        {429, "Too Many Requests"},
        {431, "Request Header Fields Too Large"},
        {451, "Unavailable For Legal Reasons"},
        {500, "Internal Server Error"},
        {501, "Not Implemented"},
        {502, "Bad Gateway"},
        {503, "Service Unavailable"},
        {504, "Gateway Timeout"},
        {505, "HTTP Version Not Supported"},
        {506, "Variant Also Negotiates"},
        {507, "Insufficient Storage"},
        {508, "Loop Detected"},
        {510, "Not Extended"},
        {511, "Network Authentication Required"},
    };
    for (auto const &[code, phrase] : registry)
        EXPECT_EQ(Status(code).str(), phrase) << code;
    EXPECT_EQ(Status(418).str(), "I'm a teapot");
}

// Every code llhttp's status map holds has a phrase, and none is an enum identifier: the
// table is complete for the map it replaces, and each phrase is a reason-phrase (RFC 9112
// §4: SP, HTAB, VCHAR, obs-text) that is not an identifier with underscores.
TEST(StatusTest, EveryMappedCodeHasAReasonPhrase) {
    struct Mapped {
        int         code;
        const char *identifier;
    };
#define QB_TEST_STATUS_ENTRY(NUM, NAME, STRING) {NUM, #NAME},
    const Mapped mapped[] = {HTTP_STATUS_MAP(QB_TEST_STATUS_ENTRY)};
#undef QB_TEST_STATUS_ENTRY
    ASSERT_GT(std::size(mapped), 90u) << "the premise: llhttp maps the registry and more";
    for (auto const &m : mapped) {
        const char *phrase = qb::http::detail::status_reason(m.code);
        ASSERT_NE(phrase, nullptr) << m.code << " " << m.identifier;
        const std::string_view p{phrase};
        EXPECT_FALSE(p.empty()) << m.code;
        EXPECT_EQ(p.find('_'), std::string_view::npos) << m.code << ": " << p;
        if (m.code != 200) {
            EXPECT_NE(p, std::string_view(m.identifier)) << m.code;
        }
        for (const char c : p) {
            const auto uc = static_cast<unsigned char>(c);
            EXPECT_TRUE(uc == 0x20 || uc == 0x09 || (uc > 0x20 && uc != 0x7f)) << m.code << ": " << p;
        }
    }
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
    // Mapped codes keep their reason phrase.
    EXPECT_EQ(std::to_string(Status(200)), "OK");
    EXPECT_EQ(std::to_string(Status(404)), "Not Found");
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
// Trailer section (trailers(), Huly QB-1073)
// ===========================================================================

// A message's trailer section is a container of its own, apart from its header fields, and it is
// allocated only when written to: the const accessor and has_trailers() read a message without one
// at no cost -- an empty section, one process-wide object.
TEST(MessageTrailersTest, TrailersAreApartFromTheHeaderSectionAndMadeOnDemand) {
    Request        req;
    const Request &creq = req;
    const Response res;
    EXPECT_FALSE(req.has_trailers());
    EXPECT_EQ(creq.trailers().header_count(), 0u);
    EXPECT_EQ(&creq.trailers(), &res.trailers()) << "a message without trailers shares the one empty section";

    (void) req.trailers(); // the non-const accessor makes the (empty) section
    EXPECT_FALSE(req.has_trailers()) << "an empty section is no trailer";
    EXPECT_NE(&creq.trailers(), &res.trailers());

    req.trailers().set_header("Grpc-Status", "0");
    req.trailers().add_header("X-Sum", "a");
    req.trailers().add_header("X-Sum", "b");
    EXPECT_TRUE(req.has_trailers());
    EXPECT_EQ(creq.trailers().header("grpc-status"), "0");
    EXPECT_EQ(creq.trailers().header("x-sum", 1), "b");
    EXPECT_FALSE(req.has_header("Grpc-Status")) << "a trailer field set to send is not a header field";
    EXPECT_EQ(req.header_count(), 0u);
}

// Copying a message copies its trailer section (each copy owns its own), moving moves it, and reset()
// drops it -- Request and Response alike.
TEST(MessageTrailersTest, TrailersFollowCopyMoveAndReset) {
    Response original;
    original.trailers().set_header("X-Sum", "1");

    Response copy = original;
    copy.trailers().set_header("X-Sum", "2");
    EXPECT_EQ(original.trailers().header("X-Sum"), "1") << "a copy owns its own section";
    EXPECT_EQ(copy.trailers().header("X-Sum"), "2");

    Response assigned;
    assigned.trailers().set_header("X-Old", "o");
    assigned = original;
    EXPECT_EQ(assigned.trailers().header("X-Sum"), "1");
    EXPECT_FALSE(assigned.trailers().has_header("X-Old"));
    const Response none;
    assigned = none;
    EXPECT_FALSE(assigned.has_trailers()) << "copying a message without trailers drops the section";

    Response moved = std::move(copy);
    EXPECT_EQ(moved.trailers().header("X-Sum"), "2");
    Response move_assigned;
    move_assigned = std::move(moved);
    EXPECT_EQ(move_assigned.trailers().header("X-Sum"), "2");

    move_assigned.reset();
    EXPECT_FALSE(move_assigned.has_trailers());

    Request req;
    req.trailers().set_header("X-Sum", "r");
    Request req_copy = req;
    EXPECT_EQ(req_copy.trailers().header("X-Sum"), "r");
    req.reset();
    EXPECT_FALSE(req.has_trailers());
    EXPECT_TRUE(req_copy.has_trailers());
}

// A received trailer field goes to trailers() and, for 3.x source compatibility, to the header fields
// after the header-section values of the same name: header() still answers the header-section value.
TEST(MessageTrailersTest, AReceivedTrailerFieldIsStoredInBothSections) {
    Response res;
    res.set_header("Server-Timing", "head");
    qb::http::detail::store_received_trailer(res, "Server-Timing", "tail");
    EXPECT_EQ(res.trailers().header("server-timing"), "tail");
    EXPECT_EQ(res.trailers().header_count(), 1u);
    EXPECT_EQ(res.header("Server-Timing"), "head");
    EXPECT_EQ(res.header("Server-Timing", 1), "tail");
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

// The authority every protocol sends -- HTTP/1.1 and WebSocket `Host`, HTTP/2 and HTTP/3
// `:authority` -- from one writer (Huly QB-1064): the host, an IPv6 literal between brackets without
// its zone identifier (RFC 9844 §6), `:port` unless it is the scheme's default.
TEST(OriginTest, AuthorityIsWhatEveryProtocolSends) {
    using qb::http::origin::authority;
    // IPv4 and a reg-name: a non-default port kept, the default one omitted.
    EXPECT_EQ(authority(qb::io::uri("http://127.0.0.1:8080/p")), "127.0.0.1:8080");
    EXPECT_EQ(authority(qb::io::uri("http://127.0.0.1/p")), "127.0.0.1");
    EXPECT_EQ(authority(qb::io::uri("http://127.0.0.1:80/p")), "127.0.0.1");
    EXPECT_EQ(authority(qb::io::uri("https://example.test/p")), "example.test");
    EXPECT_EQ(authority(qb::io::uri("https://example.test:443/p")), "example.test");
    EXPECT_EQ(authority(qb::io::uri("https://example.test:8443/p")), "example.test:8443");
    EXPECT_EQ(authority(qb::io::uri("http://example.test:443/p")), "example.test:443") << "443 is https's default, not http's";
    EXPECT_EQ(authority(qb::io::uri("ws://example.test:80/chat")), "example.test");
    EXPECT_EQ(authority(qb::io::uri("wss://example.test:443/chat")), "example.test");
    EXPECT_EQ(authority(qb::io::uri("WSS://example.test:443/chat")), "example.test") << "the scheme compares case-insensitively";
    EXPECT_EQ(authority(qb::io::uri("HTTP://example.test:80/")), "example.test");
    EXPECT_EQ(authority(qb::io::uri("xyzzy://example.test:80/")), "example.test:80") << "no default port for that scheme";
    // IPv6: between brackets, the port after them.
    EXPECT_EQ(authority(qb::io::uri("http://[2001:db8::1]:8080/p")), "[2001:db8::1]:8080");
    EXPECT_EQ(authority(qb::io::uri("https://[::1]/p")), "[::1]");
    EXPECT_EQ(authority(qb::io::uri("https://[::1]:443/p")), "[::1]");
    // An IPv6 zone identifier stays local: never sent.
    EXPECT_EQ(authority(qb::io::uri("http://[fe80::1%25eth0]:8080/p")), "[fe80::1]:8080");
    EXPECT_EQ(authority(qb::io::uri("https://[fe80::a:b%25en0]/p")), "[fe80::a:b]");
    // No host, no authority.
    EXPECT_EQ(authority(qb::io::uri("/relative/path")), "");
}

} // namespace

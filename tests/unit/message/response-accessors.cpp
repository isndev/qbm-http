/**
 * @file qbm/http/tests/unit/message/response-accessors.cpp
 * @brief Unit tests for the Response cookie/builder surface (response.h) that the
 *        existing suites leave uncovered.
 *
 * Coverage of `Response` is split today between two files that each touch a
 * disjoint slice:
 *   - message-types.cpp pins status / body / header / reset / content-type.
 *   - cookie.cpp (CookieIntegration) pins `add_cookie`, `remove_cookie` (both
 *     overloads), the non-const `cookie()`, `has_cookie`, `update_cookie_header(s)`.
 *
 * Neither exercises the fluent cookie builders, the all-args constructor, the
 * inbound Set-Cookie reparse, or the *const* accessors. This file fills exactly
 * those gaps:
 *
 *   - `Response(Status, headers, body)` — the 3-argument constructor.
 *   - `with_cookie(const Cookie&)` / `with_cookies(const CookieJar&)` — fluent
 *     builders that mutate the jar AND keep the Set-Cookie headers in sync.
 *   - `parse_set_cookie_headers()` — rebuild the internal jar from raw inbound
 *     Set-Cookie header values (and clear it when none are present).
 *   - the const-qualified `cookie(name)` / `cookies()` accessors.
 *
 * Pure logic: no socket, no event loop.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <qbm/http/cookie.h>
#include <qbm/http/response.h>
#include <qbm/http/types.h>

using qb::http::Cookie;
using qb::http::CookieJar;
using qb::http::Response;
using qb::http::Status;

namespace {

// ---------------------------------------------------------------------------
// All-args constructor: Response(Status, headers, body).
// ---------------------------------------------------------------------------

TEST(ResponseAccessors, AllArgsConstructorSeedsStatusHeadersBody) {
    qb::icase_unordered_map<std::vector<std::string>> headers;
    headers["X-Trace"]      = {"abc"};
    headers["Content-Type"] = {"text/plain; charset=utf-8"};

    Response res(Status::CREATED, headers, qb::http::Body(std::string("payload")));

    EXPECT_EQ(res.status(), Status::CREATED);
    EXPECT_EQ(res.status().code(), 201);
    EXPECT_EQ(res.header("X-Trace"), "abc");
    EXPECT_EQ(res.body().as<std::string_view>(), "payload");
    // The all-args ctor forwards headers to MessageBase, which refreshes the
    // cached ContentType helper from the seeded header.
    EXPECT_EQ(res.content_type().type(), "text/plain");
    EXPECT_EQ(res.content_type().charset(), "utf-8");
}

// ---------------------------------------------------------------------------
// Fluent cookie builders: with_cookie / with_cookies.
// ---------------------------------------------------------------------------

TEST(ResponseAccessors, WithCookieAddsToJarAndHeader) {
    Response res;
    Cookie   c("sid", "abc123");
    c.path("/admin").http_only(true);

    Response &ref = res.with_cookie(c);
    EXPECT_EQ(&ref, &res); // fluent: returns *this

    ASSERT_TRUE(res.has_cookie("sid"));
    ASSERT_NE(res.cookie("sid"), nullptr);
    EXPECT_EQ(res.cookie("sid")->value(), "abc123");
    EXPECT_EQ(res.cookie("sid")->path(), "/admin");
    EXPECT_TRUE(res.cookie("sid")->http_only());

    // A matching Set-Cookie header was emitted.
    ASSERT_TRUE(res.has_header("Set-Cookie"));
    bool found = false;
    for (const auto &h : res.headers().at("Set-Cookie")) {
        if (h.find("sid=abc123") == 0) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST(ResponseAccessors, WithCookiesReplacesJarAndSyncsHeaders) {
    Response res;
    res.with_cookie(Cookie("stale", "old")); // pre-existing cookie + header

    CookieJar jar;
    jar.add(Cookie("a", "1"));
    jar.add(Cookie("b", "2"));

    Response &ref = res.with_cookies(jar);
    EXPECT_EQ(&ref, &res);

    // The jar was fully replaced — the stale cookie is gone, the two new ones in.
    EXPECT_FALSE(res.has_cookie("stale"));
    EXPECT_TRUE(res.has_cookie("a"));
    EXPECT_TRUE(res.has_cookie("b"));
    EXPECT_EQ(res.cookies().size(), 2u);

    // Set-Cookie headers were rebuilt from scratch: exactly the two new cookies,
    // and no leftover "stale" entry.
    ASSERT_TRUE(res.has_header("Set-Cookie"));
    const auto &set_cookie = res.headers().at("Set-Cookie");
    EXPECT_EQ(set_cookie.size(), 2u);
    for (const auto &h : set_cookie) {
        EXPECT_EQ(h.find("stale="), std::string::npos);
    }
}

// ---------------------------------------------------------------------------
// parse_set_cookie_headers(): rebuild the jar from inbound raw headers.
// ---------------------------------------------------------------------------

TEST(ResponseAccessors, ParseSetCookieHeadersPopulatesJar) {
    Response res;
    res.add_header("Set-Cookie", "session=xyz; Path=/; HttpOnly");
    res.add_header("Set-Cookie", "theme=dark; Path=/");

    // The jar starts empty (add_header does not parse); parse fills it.
    EXPECT_FALSE(res.has_cookie("session"));
    res.parse_set_cookie_headers();

    ASSERT_TRUE(res.has_cookie("session"));
    ASSERT_TRUE(res.has_cookie("theme"));
    EXPECT_EQ(res.cookies().size(), 2u);

    ASSERT_NE(res.cookie("session"), nullptr);
    EXPECT_EQ(res.cookie("session")->value(), "xyz");
    EXPECT_TRUE(res.cookie("session")->http_only());
    ASSERT_NE(res.cookie("theme"), nullptr);
    EXPECT_EQ(res.cookie("theme")->value(), "dark");
}

TEST(ResponseAccessors, ParseSetCookieHeadersClearsJarWhenNonePresent) {
    Response res;
    res.with_cookie(Cookie("pre", "loaded"));
    ASSERT_TRUE(res.has_cookie("pre"));

    // No Set-Cookie header now exists from the response's own jar? with_cookie
    // emitted one; remove all headers so the reparse sees nothing to parse.
    res.headers().erase("Set-Cookie");
    res.parse_set_cookie_headers();

    // The jar is cleared first, and with no Set-Cookie header to parse it stays empty.
    EXPECT_FALSE(res.has_cookie("pre"));
    EXPECT_TRUE(res.cookies().empty());
}

// ---------------------------------------------------------------------------
// const-qualified accessors.
// ---------------------------------------------------------------------------

TEST(ResponseAccessors, ConstAccessorsReadCookieState) {
    Response res;
    res.with_cookie(Cookie("k", "v"));

    const Response &cres = res;
    ASSERT_NE(cres.cookie("k"), nullptr); // const cookie(name)
    EXPECT_EQ(cres.cookie("k")->value(), "v");
    EXPECT_EQ(cres.cookie("absent"), nullptr);

    const CookieJar &jar = cres.cookies(); // const cookies()
    EXPECT_EQ(jar.size(), 1u);
    EXPECT_TRUE(jar.has("k"));
}

// update_cookie_header() for a name absent from the jar is a no-op (early return),
// not an error, and writes no Set-Cookie header.
TEST(ResponseAccessors, UpdateCookieHeaderUnknownNameIsNoop) {
    Response res;
    EXPECT_NO_THROW(res.update_cookie_header("does-not-exist"));
    EXPECT_FALSE(res.has_header("Set-Cookie"));
}

// When re-syncing a cookie, a pre-existing Set-Cookie header with no '=' cannot
// be matched by name and must be left in place (the erase predicate skips it).
TEST(ResponseAccessors, UpdateCookieHeaderSkipsMalformedExistingSetCookie) {
    Response res;
    res.with_cookie(Cookie("sid", "v"));                 // real cookie in jar + Set-Cookie header
    res.add_header("Set-Cookie", "malformed-no-equals"); // no '=' -> predicate returns false
    EXPECT_NO_THROW(res.update_cookie_header("sid"));
    EXPECT_TRUE(res.has_header("Set-Cookie"));
}

} // namespace

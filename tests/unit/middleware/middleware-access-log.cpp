/**
 * @file qbm/http/tests/unit/middleware/middleware-access-log.cpp
 * @brief `AccessLog` and its three formats (Huly QB-90).
 *
 * Pinned: the common, combined and JSON lines byte for byte (UTC time, `-` for an empty body or an absent header,
 * Apache's escaping of `"`, `\` and non-printable bytes, JSON's escaping and `null` route); an `AccessLog` on a
 * router writes one line per routed request -- a 404 included -- with the request id `RequestIdMiddleware` gave it,
 * the same the response header carries; a throwing sink is contained; an empty sink is refused.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <qbm/http/http.h>
#include <qbm/http/middleware/access_log.h>
#include <qbm/http/middleware/request_id.h>

#include "../../shared/mock_session.h"

namespace middleware_access_log_test {

using qb::http::test::create_request;
using qb::http::test::MockSession;
using Ctx = qb::http::Context<MockSession>;

/// 2000-10-10T13:55:36.042Z
qb::wall_time
apache_example_time() {
    return qb::wall_time{std::chrono::seconds{971186136}} + std::chrono::milliseconds{42};
}

qb::http::AccessLogRecord
example_record() {
    qb::http::AccessLogRecord r;
    r.remote_address = "127.0.0.1";
    r.received       = apache_example_time();
    r.method         = "GET";
    r.target         = "/apache_pb.gif?x=1";
    r.major_version  = 1;
    r.minor_version  = 1;
    r.status         = 200;
    r.bytes          = 2326;
    r.referer        = "http://www.example.com/start.html";
    r.user_agent     = "Mozilla/4.08 [en] (Win98; I ;Nav)";
    r.duration       = std::chrono::microseconds{12345};
    r.request_id     = "req-1";
    r.route          = "/apache_pb.gif";
    return r;
}

std::string
format(qb::http::AccessLogFormatter const &f, qb::http::AccessLogRecord const &r) {
    std::string line;
    f(r, line);
    return line;
}

TEST(AccessLogFormat, CommonIsApachesLine) {
    auto r = example_record();
    EXPECT_EQ(format(qb::http::access_log_format::common, r),
              "127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] \"GET /apache_pb.gif?x=1 HTTP/1.1\" 200 2326");
    r.remote_address = "";
    r.bytes          = 0;
    r.major_version  = 2;
    EXPECT_EQ(format(qb::http::access_log_format::common, r), "- - - [10/Oct/2000:13:55:36 +0000] \"GET /apache_pb.gif?x=1 HTTP/2\" 200 -");
}

TEST(AccessLogFormat, CombinedAddsRefererAndUserAgentEscaped) {
    auto r = example_record();
    EXPECT_EQ(format(qb::http::access_log_format::combined, r),
              "127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] \"GET /apache_pb.gif?x=1 HTTP/1.1\" 200 2326 "
              "\"http://www.example.com/start.html\" \"Mozilla/4.08 [en] (Win98; I ;Nav)\"");
    r.referer    = "";
    r.user_agent = "evil\"agent\\\n\x7f";
    EXPECT_EQ(format(qb::http::access_log_format::combined, r),
              "127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] \"GET /apache_pb.gif?x=1 HTTP/1.1\" 200 2326 \"-\" \"evil\\\"agent\\\\\\x0a\\x7f\"");
}

TEST(AccessLogFormat, JsonIsOneEscapedObject) {
    auto r = example_record();
    EXPECT_EQ(format(qb::http::access_log_format::json, r),
              "{\"time\":\"2000-10-10T13:55:36.042Z\",\"remote\":\"127.0.0.1\",\"method\":\"GET\",\"target\":\"/apache_pb.gif?x=1\","
              "\"protocol\":\"HTTP/1.1\",\"status\":200,\"bytes\":2326,\"duration_seconds\":0.012345,"
              "\"referer\":\"http://www.example.com/start.html\",\"user_agent\":\"Mozilla/4.08 [en] (Win98; I ;Nav)\","
              "\"request_id\":\"req-1\",\"route\":\"/apache_pb.gif\",\"outcome\":\"responded\"}");
    r.route                = "";
    r.user_agent           = "a\"b\\c\nd\x01";
    r.outcome              = qb::http::RequestOutcome::SESSION_GONE;
    const std::string line = format(qb::http::access_log_format::json, r);
    EXPECT_NE(line.find("\"user_agent\":\"a\\\"b\\\\c\\nd\\u0001\""), std::string::npos) << line;
    EXPECT_NE(line.find("\"route\":null"), std::string::npos) << line;
    EXPECT_NE(line.find("\"outcome\":\"session_gone\""), std::string::npos) << line;
}

TEST(AccessLog, OneLinePerRoutedRequestWithItsRequestId) {
    std::vector<std::string>      lines;
    qb::http::Router<MockSession> router;
    router.use(qb::http::request_id_middleware<MockSession>());
    router.add_observer(
        qb::http::access_log<MockSession>([&lines](std::string_view line) { lines.emplace_back(line); }, qb::http::access_log_format::json));
    router.get("/users/:id", [](std::shared_ptr<Ctx> ctx) { ctx->text("hello"); });
    router.compile();

    auto session = std::make_shared<MockSession>();
    router.route(session, create_request(qb::http::method::GET, "/users/7"));
    const std::string id = session->get_response_ref().header("X-Request-ID");
    session->reset();
    router.route(session, create_request(qb::http::method::GET, "/missing"));

    ASSERT_EQ(lines.size(), 2u);
    EXPECT_NE(lines[0].find("\"request_id\":\"" + id + "\""), std::string::npos) << lines[0];
    EXPECT_NE(lines[0].find("\"route\":\"/users/:id\""), std::string::npos) << lines[0];
    EXPECT_NE(lines[0].find("\"status\":200,\"bytes\":5,"), std::string::npos) << lines[0];
    EXPECT_NE(lines[0].find("\"target\":\"/users/7\""), std::string::npos) << lines[0];
    EXPECT_NE(lines[1].find("\"status\":404"), std::string::npos) << lines[1];
    EXPECT_NE(lines[1].find("\"route\":null"), std::string::npos) << lines[1];
}

TEST(AccessLog, AThrowingSinkIsContainedAndAnEmptyOneRefused) {
    qb::http::Router<MockSession> router;
    int                           calls = 0;
    router.add_observer(qb::http::access_log<MockSession>([&calls](std::string_view) {
        ++calls;
        throw std::runtime_error("sink down");
    }));
    router.get("/x", [](std::shared_ptr<Ctx> ctx) { ctx->text("x"); });
    router.compile();
    auto session = std::make_shared<MockSession>();
    router.route(session, create_request(qb::http::method::GET, "/x"));
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(session->response_write_count(), 1u) << "the request was answered all the same";

    EXPECT_THROW((void) qb::http::access_log<MockSession>(nullptr), std::invalid_argument);
    EXPECT_THROW((void) qb::http::access_log<MockSession>([](std::string_view) {}, nullptr), std::invalid_argument);
}

} // namespace middleware_access_log_test

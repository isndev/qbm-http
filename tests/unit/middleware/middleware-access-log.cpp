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

/// The byte rules, one byte at a time: the reference the formatters' escaping is held to.
std::string
apache_escaped(std::string_view const text) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string           out;
    for (const char ch : text) {
        const auto c = static_cast<unsigned char>(ch);
        if (c == '"' || c == '\\')
            out += {'\\', ch};
        else if (c < 0x20 || c >= 0x7f)
            out += {'\\', 'x', hex[c >> 4], hex[c & 0xf]};
        else
            out += ch;
    }
    return out;
}

std::string
json_escaped(std::string_view const text) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string           out;
    for (const char ch : text) {
        const auto c = static_cast<unsigned char>(ch);
        if (ch == '"' || ch == '\\')
            out += {'\\', ch};
        else if (ch == '\n')
            out += "\\n";
        else if (ch == '\r')
            out += "\\r";
        else if (ch == '\t')
            out += "\\t";
        else if (c < 0x20)
            out += {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 0xf]};
        else
            out += ch;
    }
    return out;
}

TEST(AccessLogFormat, EveryByteIsEscapedByItsRuleAtEveryPositionAndLength) {
    // The formatters scan a field eight bytes at a time: every byte value, at every position of fields of every
    // length around the eight-byte blocks, and fields longer than any internal buffer, must escape exactly as the
    // byte rules do.
    auto r    = example_record();
    r.referer = "";
    std::vector<std::size_t> lengths;
    for (std::size_t n = 1; n <= 24; ++n)
        lengths.push_back(n);
    for (const std::size_t n : {31u, 32u, 33u, 63u, 64u, 65u, 255u, 256u, 257u, 300u, 1000u})
        lengths.push_back(n);
    const std::string common_prefix = format(qb::http::access_log_format::common, r);
    for (int b = 0; b < 256; ++b) {
        for (const std::size_t n : lengths) {
            for (std::size_t pos = 0; pos < n; pos += (n > 40 ? n / 7 + 1 : 1)) {
                std::string field(n, 'a');
                field[pos]   = static_cast<char>(b);
                r.user_agent = field;
                ASSERT_EQ(format(qb::http::access_log_format::combined, r), common_prefix + " \"-\" \"" + apache_escaped(field) + "\"")
                    << "byte " << b << " at " << pos << " of " << n;
                const std::string line = format(qb::http::access_log_format::json, r);
                ASSERT_NE(line.find(",\"user_agent\":\"" + json_escaped(field) + "\",\"request_id\":"), std::string::npos)
                    << "byte " << b << " at " << pos << " of " << n;
            }
        }
    }
    // Long fields made of bytes to escape only, and of clean bytes only.
    for (const std::size_t n : {7u, 8u, 9u, 300u, 1000u}) {
        for (const char fill : {'"', '\x01', '\x7f', '\xe9', 'z'}) {
            const std::string field(n, fill);
            r.user_agent = field;
            ASSERT_EQ(format(qb::http::access_log_format::combined, r), common_prefix + " \"-\" \"" + apache_escaped(field) + "\"");
            ASSERT_NE(format(qb::http::access_log_format::json, r).find(",\"user_agent\":\"" + json_escaped(field) + "\","), std::string::npos);
        }
    }
}

TEST(AccessLogFormat, ARecordOfEmptyFieldsIsWrittenWhole) {
    // Every view of a default record is empty and points nowhere: each format still writes its whole line.
    const qb::http::AccessLogRecord r{};
    EXPECT_EQ(format(qb::http::access_log_format::common, r), "- - - [01/Jan/1970:00:00:00 +0000] \"  HTTP/1.1\" 0 -");
    EXPECT_EQ(format(qb::http::access_log_format::combined, r), "- - - [01/Jan/1970:00:00:00 +0000] \"  HTTP/1.1\" 0 - \"-\" \"-\"");
    EXPECT_EQ(format(qb::http::access_log_format::json, r),
              "{\"time\":\"1970-01-01T00:00:00.000Z\",\"remote\":\"\",\"method\":\"\",\"target\":\"\",\"protocol\":\"HTTP/1.1\","
              "\"status\":0,\"bytes\":0,\"duration_seconds\":0.000000,\"referer\":\"\",\"user_agent\":\"\",\"request_id\":\"\","
              "\"route\":null,\"outcome\":\"responded\"}");
}

TEST(AccessLogFormat, EachLineCarriesItsOwnTimeAcrossSeconds) {
    // The formatted second is reused while the second does not change: the next second, an earlier one and the
    // milliseconds of the same second must all come out right, in both time formats.
    auto       r  = example_record();
    const auto t0 = qb::wall_time{std::chrono::seconds{971186136}};
    struct Case {
        qb::wall_time t;
        const char   *clf;
        const char   *rfc3339;
    };
    const Case cases[] = {
        {t0 + std::chrono::milliseconds{42}, "[10/Oct/2000:13:55:36 +0000]", "2000-10-10T13:55:36.042Z"},
        {t0 + std::chrono::milliseconds{999}, "[10/Oct/2000:13:55:36 +0000]", "2000-10-10T13:55:36.999Z"},
        {t0 + std::chrono::seconds{1}, "[10/Oct/2000:13:55:37 +0000]", "2000-10-10T13:55:37.000Z"},
        {t0 - std::chrono::hours{24 * 31}, "[09/Sep/2000:13:55:36 +0000]", "2000-09-09T13:55:36.000Z"},
        {t0 + std::chrono::milliseconds{7}, "[10/Oct/2000:13:55:36 +0000]", "2000-10-10T13:55:36.007Z"},
        // Before 1970: the second is rounded down, the milliseconds stay within it.
        {qb::wall_time{} - std::chrono::milliseconds{958}, "[31/Dec/1969:23:59:59 +0000]", "1969-12-31T23:59:59.042Z"},
    };
    for (const auto &c : cases) {
        r.received = c.t;
        EXPECT_NE(format(qb::http::access_log_format::common, r).find(c.clf), std::string::npos) << c.clf;
        EXPECT_NE(format(qb::http::access_log_format::json, r).find(std::string("{\"time\":\"") + c.rfc3339 + "\""), std::string::npos)
            << c.rfc3339;
    }
}

TEST(AccessLogFormat, DurationIsInSecondsRoundedToTheMicrosecond) {
    auto r = example_record();
    struct Case {
        qb::duration d;
        const char  *text;
    };
    const Case cases[] = {
        {qb::duration{0}, "0.000000"},
        {std::chrono::nanoseconds{499}, "0.000000"},
        {std::chrono::nanoseconds{500}, "0.000001"},
        {std::chrono::nanoseconds{2500}, "0.000003"},
        {std::chrono::microseconds{12345}, "0.012345"},
        {std::chrono::milliseconds{1500}, "1.500000"},
        {std::chrono::seconds{3723} + std::chrono::microseconds{42}, "3723.000042"},
        {std::chrono::nanoseconds{-5}, "0.000000"},
    };
    for (const auto &c : cases) {
        r.duration = c.d;
        EXPECT_NE(format(qb::http::access_log_format::json, r).find(std::string(",\"duration_seconds\":") + c.text + ","), std::string::npos)
            << c.text;
    }
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

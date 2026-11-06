/**
 * @file qbm/http/tests/unit/sse/sse-format.cpp
 * @brief The wire form of a Server-Sent Event (Huly QB-86): one case per field, the data split, the comment and
 *        retry lines, `Last-Event-ID`.
 *
 * The format is the WHATWG HTML Standard's ("Server-sent events"): a field is `name: value` ended by LF, an event
 * ends with a blank line, a line starting with `:` is a comment. What a client does with it (joins the `data:` lines
 * with LF, drops a trailing LF, dispatches nothing without a `data:` line) is why each line below is what it is.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <chrono>
#include <string>

#include <gtest/gtest.h>

#include <qbm/http/http.h>

using namespace std::chrono_literals;
using qb::http::sse::Event;

namespace sse_format_test {

TEST(SseFormat, DataAloneIsOneDataLineAndABlankLine) {
    EXPECT_EQ(qb::http::sse::format(Event{.data = "hello"}), "data: hello\n\n");
}

TEST(SseFormat, ANameGoesOnAnEventLineFirst) {
    EXPECT_EQ(qb::http::sse::format(Event{.name = "tick", .data = "1"}), "event: tick\ndata: 1\n\n");
}

TEST(SseFormat, AnIdGoesOnAnIdLine) {
    EXPECT_EQ(qb::http::sse::format(Event{.data = "x", .id = "42"}), "id: 42\ndata: x\n\n");
}

TEST(SseFormat, ARetryGoesOnARetryLineInMilliseconds) {
    EXPECT_EQ(qb::http::sse::format(Event{.data = "x", .retry = 1500ms}), "retry: 1500\ndata: x\n\n");
    EXPECT_EQ(qb::http::sse::format(Event{.data = "x", .retry = std::chrono::milliseconds{0}}), "retry: 0\ndata: x\n\n");
}

TEST(SseFormat, EveryFieldInOrderEventIdRetryData) {
    EXPECT_EQ(qb::http::sse::format(Event{.name = "update", .data = "payload", .id = "7", .retry = 250ms}),
              "event: update\nid: 7\nretry: 250\ndata: payload\n\n");
}

TEST(SseFormat, MultiLineDataIsOneDataLinePerLine) {
    EXPECT_EQ(qb::http::sse::format(Event{.data = "one\ntwo\nthree"}), "data: one\ndata: two\ndata: three\n\n");
}

TEST(SseFormat, CrLfAndCrEndALineToo) {
    EXPECT_EQ(qb::http::sse::format(Event{.data = "a\r\nb\rc"}), "data: a\ndata: b\ndata: c\n\n");
}

TEST(SseFormat, ATrailingLineBreakIsKeptByAnEmptyLastLine) {
    // The client appends LF to each value and drops the last LF when it dispatches: "last\n" round-trips only with an
    // empty last line (`data: last`, `data: `).
    EXPECT_EQ(qb::http::sse::format(Event{.data = "last\n"}), "data: last\ndata: \n\n");
    EXPECT_EQ(qb::http::sse::format(Event{.data = "last\r\n"}), "data: last\ndata: \n\n");
    EXPECT_EQ(qb::http::sse::format(Event{.data = "\n"}), "data: \ndata: \n\n");
}

TEST(SseFormat, ALoneTrailingCrAndACrBeforeACrLfEndLinesToo) {
    EXPECT_EQ(qb::http::sse::format(Event{.data = "a\r"}), "data: a\ndata: \n\n");
    EXPECT_EQ(qb::http::sse::format(Event{.data = "\r\r\n"}), "data: \ndata: \ndata: \n\n") << "a CR, then a CRLF: two line breaks, as LF LF";
}

TEST(SseFormat, ANameOrAnIdOfLineBreaksAloneIsNoField) {
    // An `id:` with an empty value would reset the client's Last-Event-ID: a value that is only line breaks is left out.
    EXPECT_EQ(qb::http::sse::format(Event{.data = "x", .id = "\r\n"}), "data: x\n\n");
    EXPECT_EQ(qb::http::sse::format(Event{.name = "\n", .data = "x"}), "data: x\n\n");
}

TEST(SseFormat, ALineBreakInANameAnIdOrACommentIsDropped) {
    // A value a client supplied (an id echoed from Last-Event-ID) must not start another field.
    EXPECT_EQ(qb::http::sse::format(Event{.name = "a\nb", .data = "x", .id = "1\r\ndata: forged"}),
              "event: ab\nid: 1data: forged\ndata: x\n\n");
    EXPECT_EQ(qb::http::sse::comment_line("ka\n\ndata: forged"), ": kadata: forged\n\n");
}

TEST(SseFormat, AnEmptyLineInsideTheDataIsKept) {
    EXPECT_EQ(qb::http::sse::format(Event{.data = "a\n\nb"}), "data: a\ndata: \ndata: b\n\n") << "the client joins them: a, empty, b";
}

TEST(SseFormat, EmptyDataStillWritesADataLine) {
    EXPECT_EQ(qb::http::sse::format(Event{.name = "ping"}), "event: ping\ndata: \n\n") << "without a data: line a client dispatches nothing";
}

TEST(SseFormat, NothingElseIsEscaped) {
    EXPECT_EQ(qb::http::sse::format(Event{.data = "{\"json\": \"with: colons\"} and \\backslashes"}),
              "data: {\"json\": \"with: colons\"} and \\backslashes\n\n");
}

TEST(SseFormat, ACommentLineIsAColonAndABlankLine) {
    EXPECT_EQ(qb::http::sse::comment_line("keep-alive"), ": keep-alive\n\n");
    EXPECT_EQ(qb::http::sse::comment_line(""), ": \n\n");
}

TEST(SseFormat, ARetryLineAlone) {
    EXPECT_EQ(qb::http::sse::retry_line(3000ms), "retry: 3000\n\n");
}

TEST(SseFormat, LastEventIdIsTheRequestHeaderOrEmpty) {
    qb::http::Request request;
    EXPECT_TRUE(qb::http::sse::last_event_id(request).empty());
    request.set_header("Last-Event-ID", "abc-9");
    EXPECT_EQ(qb::http::sse::last_event_id(request), "abc-9");
    qb::http::Request lower;
    lower.set_header("last-event-id", "lc");
    EXPECT_EQ(qb::http::sse::last_event_id(lower), "lc") << "a field name is looked up case-insensitively";
}

TEST(SseFormat, TheContentTypeIsTheEventStreamOne) {
    EXPECT_EQ(qb::http::sse::content_type, "text/event-stream; charset=utf-8");
}

} // namespace sse_format_test

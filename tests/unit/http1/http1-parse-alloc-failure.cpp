/**
 * @file qbm/http/tests/unit/http1/http1-parse-alloc-failure.cpp
 * @brief An allocation that fails inside one of llhttp's callbacks refuses the message: nothing unwinds through llhttp.
 *
 * llhttp is C, and it calls the parser's callbacks from its own frames. An exception thrown in one -- an allocation
 * that stores a field line, the target, a chunk, a trailer field, the Host value an absolute-form target rewrites --
 * unwound through those frames, which is undefined behaviour, up to the protocol's noexcept getMessageSize(), which
 * terminated the process (review r1 N2 of Huly QB-1186). The callbacks are noexcept now, and the ones that allocate
 * refuse the message instead: 503 for an allocation failure.
 *
 * This binary replaces the global operator new with one that can be told to fail its N-th allocation from now, once,
 * and feeds a request (then a response) piece by piece. For each piece, every one of its allocations is made to fail
 * in turn, on a fresh parser fed the pieces before it normally: the parse must end with an error and the 503 refusal,
 * never with an exception, and every swept piece must allocate at least once, or the sweep proves nothing there.
 *
 * One piece is fed unarmed: the one that ends the request target, which qb::io::uri's in-place readers read. They are
 * noexcept, as every parsing entry point of qb::io::uri is: an allocation failure inside them terminates, by qb's
 * convention (qb/src/qb/io/uri.h), before any exception reaches llhttp.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <qb/system/allocator/pipe.h>

#include <qbm/http/1.1/protocol/base.h>
#include <qbm/http/1.1/protocol/server.h>
#include <qbm/http/http.h>

namespace http1_parse_alloc_failure_test {

/// 0: every allocation succeeds. k > 0: the k-th allocation from now throws std::bad_alloc, and the next ones succeed.
std::size_t g_fail_in = 0;
/// The armed allocation was reached, and failed.
bool g_fired = false;

void
arm(std::size_t const nth) noexcept {
    g_fired   = false;
    g_fail_in = nth;
}

/// Disarms, and tells whether the armed allocation failed.
bool
disarm() noexcept {
    g_fail_in = 0;
    return g_fired;
}

void *
allocate(std::size_t const size) {
    if (g_fail_in != 0 && --g_fail_in == 0) {
        g_fired = true;
        throw std::bad_alloc{};
    }
    if (void *const memory = std::malloc(size == 0 ? 1 : size))
        return memory;
    throw std::bad_alloc{};
}

} // namespace http1_parse_alloc_failure_test

// The replaceable allocation functions of the whole program, the nothrow forms included, all over malloc and free: a
// form left to the runtime pairs with one replaced here -- std::get_temporary_buffer() takes the nothrow new, gives
// back with the sized delete, and AddressSanitizer reports the mix. The aligned forms keep the runtime's own pair.
void *
operator new(std::size_t size) {
    return http1_parse_alloc_failure_test::allocate(size);
}
void *
operator new[](std::size_t size) {
    return http1_parse_alloc_failure_test::allocate(size);
}
void *
operator new(std::size_t size, std::nothrow_t const &) noexcept {
    try {
        return http1_parse_alloc_failure_test::allocate(size);
    } catch (...) {
        return nullptr;
    }
}
void *
operator new[](std::size_t size, std::nothrow_t const &) noexcept {
    try {
        return http1_parse_alloc_failure_test::allocate(size);
    } catch (...) {
        return nullptr;
    }
}
void
operator delete(void *memory, std::nothrow_t const &) noexcept {
    std::free(memory);
}
void
operator delete[](void *memory, std::nothrow_t const &) noexcept {
    std::free(memory);
}
void
operator delete(void *memory) noexcept {
    std::free(memory);
}
void
operator delete[](void *memory) noexcept {
    std::free(memory);
}
void
operator delete(void *memory, std::size_t) noexcept {
    std::free(memory);
}
void
operator delete[](void *memory, std::size_t) noexcept {
    std::free(memory);
}

namespace http1_parse_alloc_failure_test {

/// A piece of a message, its callbacks named, and what llhttp returns for it when nothing fails.
struct Piece {
    std::string_view bytes;
    bool             swept;  ///< every allocation it makes is made to fail in turn
    int              normal; ///< HPE_OK, HPE_PAUSED at the end of the header section, HPE_CB_MESSAGE_COMPLETE at the end
};

std::string const kChunk(5120, 'x'); // past the body pipe's first 4 KiB: on_body grows it

std::string const kChunkedBody = "1400\r\n" + kChunk + "\r\n";

// Names and values past the small-string buffer, and each trailer longer than every field before it: the parser's
// key and value buffers keep their capacity from one field to the next, and only a longer one allocates.
std::vector<Piece> const kRequest = {
    {"GET http://an-authority-longer-than-the-sso.example.test/a/path/longer/than/the/sso", true, HPE_OK}, // on_url
    {" HTTP/1.1\r\n", false, HPE_OK}, // on_url_complete: qb::io::uri's noexcept reader (see the file comment)
    {"Host: h\r\nTransfer-Encoding: chunked\r\nX-A-Field-Name-Longer-Than-The-Sso: a field value longer than the sso\r\n", true,
     HPE_OK},                     // on_header_field, which stores the field before it, and on_header_value
    {"\r\n", true, HPE_PAUSED},   // on_headers_complete: the last field stored, Transfer-Encoding read, Host rewritten
    {kChunkedBody, true, HPE_OK}, // on_body
    {"0\r\nX-A-Trailer-Field-Name-Longer-Than-Every-Field-Name-Before-It: a trailer value longer than every value before it\r\n\r\n", true,
     HPE_CB_MESSAGE_COMPLETE}, // a trailer field, on_value_end, on_message_complete
};

std::vector<Piece> const kResponse = {
    {"HTTP/1.1 200 OK\r\n", false, HPE_OK}, // on_status, which allocates nothing
    {"Transfer-Encoding: chunked\r\nX-A-Field-Name-Longer-Than-The-Sso: a field value longer than the sso\r\n", true, HPE_OK},
    {"\r\n", true, HPE_PAUSED},
    {kChunkedBody, true, HPE_OK},
    {"0\r\nX-A-Trailer-Field-Name-Longer-Than-Every-Field-Name-Before-It: a trailer value longer than every value before it\r\n\r\n", true,
     HPE_CB_MESSAGE_COMPLETE},
};

template <typename Message>
int
parse(qb::http::Parser<Message> &parser, std::string_view const bytes) {
    return parser.parse(bytes.data(), bytes.size());
}

/// Feeds the pieces before @p end as a connection does, resuming after the header section.
template <typename Message>
::testing::AssertionResult
feed_before(qb::http::Parser<Message> &parser, std::vector<Piece> const &pieces, std::size_t const end) {
    for (std::size_t i = 0; i < end; ++i) {
        if (int const result = parse(parser, pieces[i].bytes); result != pieces[i].normal)
            return ::testing::AssertionFailure() << "piece " << i << " parsed to " << result << ", not " << pieces[i].normal;
        if (pieces[i].normal == HPE_PAUSED)
            parser.resume();
    }
    return ::testing::AssertionSuccess();
}

/// For each swept piece of @p pieces, each of its allocations made to fail in turn: the parse ends with an error and
/// @p refusal, no exception leaves it. Returns the number of failures injected.
template <typename Message>
std::size_t
sweep(std::vector<Piece> const &pieces, int const refusal) {
    std::size_t injected = 0;
    for (std::size_t i = 0; i < pieces.size(); ++i) {
        if (!pieces[i].swept)
            continue;
        std::size_t failed_here = 0;
        for (std::size_t nth = 1;; ++nth) {
            qb::http::Parser<Message> parser;
            EXPECT_TRUE(feed_before(parser, pieces, i));
            int  result  = HPE_OK;
            bool escaped = false;
            arm(nth);
            try {
                result = parse(parser, pieces[i].bytes);
            } catch (...) {
                escaped = true;
            }
            if (!disarm()) { // the piece made fewer than nth allocations: its parse is the normal one
                EXPECT_FALSE(escaped) << "piece " << i;
                EXPECT_EQ(result, pieces[i].normal) << "piece " << i;
                break;
            }
            ++failed_here;
            EXPECT_FALSE(escaped) << "piece " << i << ", allocation " << nth << ": the exception unwound through llhttp";
            if (escaped)
                break;
            EXPECT_NE(result, HPE_OK) << "piece " << i << ", allocation " << nth;
            EXPECT_NE(result, pieces[i].normal) << "piece " << i << ", allocation " << nth;
            EXPECT_EQ(parser.refusal_status(), refusal) << "piece " << i << ", allocation " << nth;
        }
        EXPECT_GT(failed_here, 0u) << "piece " << i << " allocated nothing: the sweep proves nothing there";
        ::testing::Test::RecordProperty("piece_" + std::to_string(i) + "_allocations_failed", static_cast<int>(failed_here));
        injected += failed_here;
    }
    return injected;
}

TEST(Http1ParseAllocFailure, EveryAllocationOfARequestThatFailsRefusesItWith503) {
    EXPECT_GE(sweep<qb::http::Request>(kRequest, HTTP_STATUS_SERVICE_UNAVAILABLE), 5u);
}

TEST(Http1ParseAllocFailure, EveryAllocationOfAResponseThatFailsFailsItsParse) {
    EXPECT_GE(sweep<qb::http::Response>(kResponse, HTTP_STATUS_SERVICE_UNAVAILABLE), 4u);
}

/// The server session's refusal hook, observable (http1-protocol-framing.cpp's).
struct RefusingServerFakeIO {
    using base_io_t = RefusingServerFakeIO;

    qb::allocator::pipe<char> input;
    int                       request_count = 0;
    std::vector<int>          refusals;

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }

    void
    http1_refuse_request(qb::http::Status status) noexcept {
        refusals.push_back(status.code());
    }

    void
    on(qb::http::Request &&) {
        ++request_count;
    }
};

// The server's side: a request whose header section cannot be stored is handed to the session for its 503, and the
// protocol stays valid for that answer. On the base the exception reached getMessageSize(), noexcept: terminate.
TEST(Http1ParseAllocFailure, TheServerAnswersARequestItCannotStore503) {
    RefusingServerFakeIO                             io;
    qb::protocol::http::server<RefusingServerFakeIO> proto(io);
    for (std::size_t i = 0; i < 3; ++i) {
        std::memcpy(io.input.allocate_back(kRequest[i].bytes.size()), kRequest[i].bytes.data(), kRequest[i].bytes.size());
        EXPECT_EQ(proto.getMessageSize(), 0u) << "piece " << i;
    }
    std::memcpy(io.input.allocate_back(kRequest[3].bytes.size()), kRequest[3].bytes.data(), kRequest[3].bytes.size());
    arm(1); // the last field line of the header section, stored when the section ends
    EXPECT_EQ(proto.getMessageSize(), 0u);
    EXPECT_TRUE(disarm());
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.refusals, std::vector<int>{HTTP_STATUS_SERVICE_UNAVAILABLE});
    EXPECT_TRUE(proto.ok()) << "the io answers before the connection ends";
}

} // namespace http1_parse_alloc_failure_test

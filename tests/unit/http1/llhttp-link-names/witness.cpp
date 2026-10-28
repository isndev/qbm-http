/**
 * @file qbm/http/tests/unit/http1/llhttp-link-names/witness.cpp
 * @brief qbm-http's llhttp fork and Node's http_parser in ONE program: each runs its own code (Huly QB-1139).
 *
 * The fork's `http_` prefix keeps it from colliding with a system llhttp, but http_parser uses the
 * same prefix and two of its functions carry the fork's exact names, with other signatures:
 * `http_should_keep_alive` and `http_errno_name`. A program that linked both held two definitions
 * of each, and the link line chose between them. The fork now links as `qb_` + its upstream name
 * (`qb_llhttp_should_keep_alive`), through the `#define`s of src/qbm/http/vendor/llhttp.h; source
 * keeps writing `http_should_keep_alive`. This test links the stand-in of foreign-http-parser.cpp
 * BEFORE qbm-http and asserts both sides:
 *
 *   - the stand-in's two functions are in the program and are what a translation unit that
 *     includes nothing of qbm-http reaches (caller.cpp);
 *   - qbm-http's HTTP/1.1 server protocol frames a `Connection: close` request on the fork's own
 *     `http_should_keep_alive` -- keep_alive false -- and never calls the stand-in, whose answer
 *     would have been "keep alive";
 *   - in this translation unit `http_should_keep_alive` names a different function from the
 *     stand-in's.
 *
 * Without the renaming the link holds two `http_should_keep_alive`: GNU ld and MSVC refuse it, and
 * ld64 warns, keeps one, and the request above comes out keep-alive.
 */

#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>

#include <qb/system/allocator/pipe.h>

#include <qbm/http/1.1/protocol/server.h>
#include <qbm/http/http.h>

namespace llhttp_link_names_test {

int           foreign_marker();
std::uint32_t foreign_calls();
void const   *foreign_keep_alive_address();
int           call_foreign_keep_alive();
const char   *call_foreign_errno_name();

// The socket-less IO the HTTP/1.1 protocol needs, as http1-protocol-framing.cpp drives it.
struct ServerFakeIO {
    using base_io_t = ServerFakeIO;

    qb::allocator::pipe<char>        input;
    int                              request_count = 0;
    std::optional<qb::http::Request> last_request;

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }

    void
    on(qb::http::Request &&request) {
        ++request_count;
        last_request = std::move(request);
    }
};

TEST(LlhttpLinkNames, HttpParserInTheProgramIsReachableAndIsNotTheForkQbmHttpRuns) {
    ASSERT_EQ(foreign_marker(), 0x5eed) << "the http_parser stand-in's object must be part of this link";

    // A translation unit that includes nothing of qbm-http resolves both names to http_parser.
    const std::uint32_t before_calls = foreign_calls();
    EXPECT_EQ(call_foreign_keep_alive(), 0x5eed);
    EXPECT_STREQ(call_foreign_errno_name(), "FOREIGN_HTTP_PARSER");
    EXPECT_EQ(foreign_calls(), before_calls + 2);

    // qbm-http's parser, on the fork: `Connection: close` is not keep-alive.
    const std::uint32_t                      before_parse = foreign_calls();
    ServerFakeIO                             io;
    qb::protocol::http::server<ServerFakeIO> proto(io);
    constexpr std::string_view               request = "GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n";
    std::memcpy(io.input.allocate_back(request.size()), request.data(), request.size());
    const std::size_t size = proto.getMessageSize();
    ASSERT_GT(size, 0u);
    proto.onMessage(size);
    io.input.free_front(size);
    ASSERT_EQ(io.request_count, 1);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_FALSE(io.last_request->keep_alive) << "the fork's http_should_keep_alive must decide, not http_parser's";
    EXPECT_EQ(foreign_calls(), before_parse) << "qbm-http must never call http_parser";

    // Here `http_should_keep_alive` is spelled through qbm-http's headers: it names the fork's copy.
    EXPECT_NE(reinterpret_cast<void const *>(&http_should_keep_alive), foreign_keep_alive_address());
}

} // namespace llhttp_link_names_test

/**
 * @file unit/security/content-length-preallocation.cpp
 * @brief A declared `Content-Length` must not let a peer pre-commit heap it never fills.
 *
 * `Content-Length` is peer-supplied and is known at end-of-headers — before a single body byte has
 * arrived. `on_headers_complete()` used to honour it verbatim, up to `MAX_BODY_SIZE` (100 MB), on
 * every request. A ~40-byte request that announces a huge body and then sends nothing therefore
 * pinned 100 MB of heap for the connection's whole idle lifetime: roughly 2.6 million times
 * amplification, multiplied by however many connections the peer opens. Nothing about it required
 * a malformed message — a plain, well-formed request header is enough.
 *
 * The reservation was also pure waste: it targeted `msg.body().raw()`, but the body accumulates in
 * the parser's separate `_chunked` buffer and `on_message_complete()` **move-assigns** `_chunked`
 * over `msg.body().raw()` — which deallocates whatever was reserved. So that allocation was never
 * used by anything, on any path. The reserve is on `_chunked` now, for a Parser driven directly, which reads the body
 * into it; the h1 protocol, server and client, copies a declared body from its input buffer, so its parser reserves
 * nothing (Huly QB-1248). Two protocol-level oracles hold that: the capacity a following chunked body adopts (the
 * parser's buffer, after a declared body at the reserve's cap, read after a reset() of the parser), and the allocations
 * a declared body costs after a chunked one, against after a declared one (it self-skips like oracle 2 below).
 *
 * For the parser itself, two oracles, because one of them is not available everywhere:
 *
 *   1. `body().raw().capacity()` after a headers-only parse. Allocator-independent, works under
 *      every preset, and observes the exact buffer the old reserve targeted.
 *   2. A replaced global `operator new` counting bytes while (and only while) the parser runs. This
 *      is the stronger oracle — it measures how much heap a peer can force the server to commit per
 *      request, so it cannot be satisfied by moving an unbounded reserve to a different buffer.
 *      A replaced `operator new` is easy to render vacuous — a sanitizer runtime may intercept
 *      ahead of it, and the compiler will happily elide a probe allocation — and a counter stuck at
 *      zero would make every budget assertion pass for the wrong reason. So
 *      `allocation_counter_is_live()` verifies the instrument (opaque size, buffer touched) and the
 *      check self-skips rather than passing vacuously. Verified live under both `release` and
 *      `sanitize`; with the reserve restored, a 72-byte request committed 134 217 928 bytes in both.
 *      Oracle 2 is compiled out under ThreadSanitizer — see QB_TEST_TSAN_ACTIVE below.
 *
 * qb - C++ Actor Framework
 * Copyright (C) 2011-2026 isndev (www.qbaf.io). All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <atomic>
#include <cstdio>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <new>
#include <optional>
#include <string>
#include <string_view>

#ifdef _MSC_VER
#include <malloc.h> // _aligned_malloc / _aligned_free (see the aligned pair below)
#endif

#include <gtest/gtest.h>

#include <qbm/http/1.1/protocol/base.h>
#include <qbm/http/1.1/protocol/client.h>
#include <qbm/http/1.1/protocol/server.h>
#include <qbm/http/http.h>

#include "../../shared/allocation_counter.h" // g_counting / AllocScope / the replaced operator new / allocation_counter_is_live()

using namespace qb::http;

namespace {

/// Heap a single request is allowed to commit before its body arrives. Generous next to the 64 KiB
/// reserve hint (the parser also allocates for headers, the message object and the URL), and three
/// orders of magnitude below the 100 MB a declared Content-Length used to buy.
constexpr std::size_t kPerRequestBudget = 1u * 1024u * 1024u;

std::string
headers_only(std::size_t declared_length) {
    return "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: " + std::to_string(declared_length) + "\r\n\r\n";
}

TEST(ContentLengthPreallocation, HugeDeclaredBodyThatNeverArrivesCommitsNoHeap) {
    // The largest body the parser accepts at all — the worst case a peer can legitimately declare.
    const std::string raw = headers_only(protocol_limits::MAX_BODY_SIZE);
    ASSERT_LT(raw.size(), std::size_t{128}) << "the whole attack is this many bytes";

    qb::http::Parser<Request> parser;
    std::size_t               used = 0;
    {
        AllocScope scope;
        parser.parse(raw.data(), raw.size());
        used = AllocScope::bytes();
    }

    // Headers parsed fine — this is a well-formed request, not a rejected one.
    EXPECT_TRUE(parser.headers_completed());
    EXPECT_EQ(parser.get_parsed_message().header("Host"), "example.test");

    // Oracle 1 — always available: the buffer the old reserve targeted must not have been sized
    // from the peer's claim. (It is also never used: on_message_complete move-assigns over it.)
    EXPECT_LE(parser.get_parsed_message().body().raw().capacity(), protocol_limits::MAX_BODY_RESERVE_HINT)
        << "the message body buffer was pre-sized from the declared Content-Length";

    // Oracle 2 — release preset only, see the file header.
    if (!allocation_counter_is_live())
        GTEST_SKIP() << "the operator new replacement is not observing allocations on this toolchain; "
                        "the capacity oracle above still ran";
    EXPECT_LE(used, kPerRequestBudget) << raw.size() << " bytes of request caused " << used
                                       << " bytes of heap to be committed before any body byte arrived — a peer can "
                                          "multiply this by its connection count";
}

TEST(ContentLengthPreallocation, CommittedHeapDoesNotScaleWithTheDeclaredLength) {
    // The real signature of the defect: heap commitment tracking the *claim* rather than the data.
    // Two requests identical but for the declared length must cost about the same.
    if (!allocation_counter_is_live())
        GTEST_SKIP() << "the operator new replacement is not observing allocations on this toolchain";
    auto measure = [](std::size_t declared) {
        const std::string         raw = headers_only(declared);
        qb::http::Parser<Request> parser;
        AllocScope                scope;
        parser.parse(raw.data(), raw.size());
        return AllocScope::bytes();
    };

    const std::size_t small = measure(1024);
    const std::size_t huge  = measure(protocol_limits::MAX_BODY_SIZE);

    EXPECT_LE(huge, small + kPerRequestBudget) << "declaring " << protocol_limits::MAX_BODY_SIZE << " instead of 1024 cost " << (huge - small)
                                               << " extra bytes: the parser is still sizing its buffers from an unverified peer claim";
}

TEST(ContentLengthPreallocation, DeclaredBodyStillParsesCorrectlyWhenItActuallyArrives) {
    // The cap must not change behaviour for a real body — including one comfortably larger than the
    // reserve hint, which now grows geometrically instead of being pre-sized.
    const std::string payload(protocol_limits::MAX_BODY_RESERVE_HINT * 3, 'z');
    const std::string raw = headers_only(payload.size()) + payload;

    qb::http::Parser<Request> parser;
    ASSERT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED) << "parser pauses at end-of-headers";
    ASSERT_TRUE(parser.headers_completed());

    // Second pass: resume and feed the body.
    parser.resume();
    const char *body_at = raw.data() + (raw.size() - payload.size());
    EXPECT_EQ(parser.parse(body_at, payload.size()), HPE_CB_MESSAGE_COMPLETE);

    const auto &msg = parser.get_parsed_message();
    EXPECT_EQ(msg.body().raw().size(), payload.size());
    EXPECT_EQ(std::string(msg.body().raw().begin(), msg.body().raw().size()), payload);
}

/// What a parser's two messages cost, read @p head then @p body each time -- a kept connection: the parser is
/// reset() between messages, as the protocol does. The allocations are counted over the body only (resume() and the
/// body's bytes): a first message's buffer came with the parser, outside any count.
struct kept_reading {
    std::size_t first_capacity = 0, second_capacity = 0; ///< the message body's buffer, after each message
    std::size_t first_count = 0, second_count = 0;       ///< the allocations reading each body made
};

[[nodiscard]] kept_reading
read_two_messages(const std::string &head, const std::string &body) {
    qb::http::Parser<Request> parser;
    kept_reading              reading;
    for (int message = 0; message < 2; ++message) {
        if (message == 1) {
            parser.reset();
        }
        EXPECT_EQ(parser.parse(head.data(), head.size()), HPE_PAUSED) << "message " << message;
        {
            AllocScope scope;
            parser.resume();
            EXPECT_EQ(parser.parse(body.data(), body.size()), HPE_CB_MESSAGE_COMPLETE) << "message " << message;
            (message == 0 ? reading.first_count : reading.second_count) = AllocScope::count();
        }
        (message == 0 ? reading.first_capacity : reading.second_capacity) = parser.get_parsed_message().body().raw().capacity();
    }
    return reading;
}

/// A chunked body of one chunk of @p payload.
[[nodiscard]] std::string
one_chunk(const std::string &payload) {
    char size[32];
    std::snprintf(size, sizeof size, "%zx\r\n", payload.size());
    return size + payload + "\r\n0\r\n\r\n";
}

// The body buffer is moved into each message, so from the second message of a kept connection it was null, and the
// first write of a body took the pipe's slow path: 8 KiB for five octets, twice the first message's (Huly QB-1248).
// Every body starts from the pipe's initial buffer now, declared or chunked -- one allocation, the buffer itself --
// and a first write past it grows as the first message's did, in one allocation, not the initial buffer and then a
// second.
TEST(ContentLengthPreallocation, EveryBodyOfAKeptConnectionStartsFromTheInitialBuffer) {
    const std::size_t initial = qb::allocator::pipe<char>{}.capacity();
    const std::string head    = "POST /upload HTTP/1.1\r\nHost: example.test\r\n";
    const std::string chunked = head + "Transfer-Encoding: chunked\r\n\r\n";
    const std::string large(initial + 904, 'z');
    // Warm: the first null buffer restore_body_buffer() sees reads the pipe's initial size once (a one-time allocation)
    // that must not land in a counted scope below, whichever case runs first.
    (void) read_two_messages(chunked, one_chunk("warm"));

    const auto declared = read_two_messages(head + "Content-Length: 5\r\n\r\n", "hello");
    EXPECT_EQ(declared.second_capacity, initial) << "a declared body";
    EXPECT_EQ(declared.first_capacity, initial);
    const auto small = read_two_messages(chunked, one_chunk("hello"));
    EXPECT_EQ(small.second_capacity, initial) << "a chunked body";
    const auto past = read_two_messages(chunked, one_chunk(large));
    EXPECT_EQ(past.second_capacity, past.first_capacity) << "a first write past the initial buffer grows as the first message's";
    const auto declared_past = read_two_messages(head + "Content-Length: " + std::to_string(large.size()) + "\r\n\r\n", large);
    EXPECT_EQ(declared_past.second_capacity, declared_past.first_capacity) << "so does a declared one";
    if (allocation_counter_is_live()) {
        EXPECT_EQ(small.first_count, 0u) << "the first body writes into the buffer the parser came with";
        EXPECT_EQ(small.second_count, 1u) << "the second takes the initial buffer, once";
        EXPECT_EQ(past.first_count, 1u) << "one growth";
        EXPECT_EQ(past.second_count, 1u) << "one growth from null, not the initial buffer and then a second";
        // A declared length is reserved at the end of the header section: a Parser driven directly over the body writes
        // into that reserve, and the body's bytes allocate nothing (the protocol copies such a body from its input).
        EXPECT_EQ(declared_past.first_count, 0u) << "a declared body past the initial buffer is written into its reserve";
        EXPECT_EQ(declared_past.second_count, 0u) << "on a kept connection too";
        EXPECT_EQ(declared.second_count, 0u) << "a declared body that fits the initial buffer is written into it";
    }
}

// A message without a body allocates nothing for one, even after a body left the buffer null: a GET after a chunked
// message costs what a GET on a fresh parser costs.
TEST(ContentLengthPreallocation, AMessageWithoutABodyAllocatesNoBodyBuffer) {
    if (!allocation_counter_is_live())
        GTEST_SKIP() << "the operator new replacement is not observing allocations on this toolchain";
    const std::string get       = "GET /x HTTP/1.1\r\nHost: example.test\r\n\r\n";
    const auto        count_get = [&get](qb::http::Parser<Request> &parser) {
        AllocScope scope;
        EXPECT_EQ(parser.parse(get.data(), get.size()), HPE_PAUSED);
        return AllocScope::count();
    };
    qb::http::Parser<Request> fresh;
    const std::size_t         on_fresh = count_get(fresh);

    qb::http::Parser<Request> kept;
    const std::string         head = "POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n";
    const std::string         body = "5\r\nhello\r\n0\r\n\r\n";
    ASSERT_EQ(kept.parse(head.data(), head.size()), HPE_PAUSED);
    kept.resume();
    ASSERT_EQ(kept.parse(body.data(), body.size()), HPE_CB_MESSAGE_COMPLETE); // the body buffer moved into the message: null
    kept.reset();
    EXPECT_EQ(count_get(kept), on_fresh) << "a GET after a chunked body allocated a body buffer";
}

// The h1 protocol, server and client, copies a declared body from its input buffer (getMessageSize()); only a chunked
// body is read into the parser's buffer. So the protocol reserves nothing for a declared one: before, a declared body
// at the reserve's cap held 64 KiB in that buffer for the connection's lifetime, and a declared body after a chunked one
// took the initial buffer back for nothing (Huly QB-1248). Driven without a socket, as http1-protocol-framing does.
struct server_io {
    using base_io_t = server_io;
    qb::allocator::pipe<char>        input;
    std::optional<qb::http::Request> last;
    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }
    void
    on(qb::http::Request &&request) {
        last = std::move(request);
    }
};

struct client_io {
    using base_io_t = client_io;
    qb::allocator::pipe<char>         input;
    std::optional<qb::http::Response> last;
    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }
    [[nodiscard]] bool
    http1_response_body_forbidden() const noexcept {
        return false;
    }
    void
    on(qb::http::Response &&response) {
        last = std::move(response);
    }
};

/// Hands @p wire to the protocol as one read; returns the allocations framing and delivering it made (the read's own
/// copy into the input buffer is outside the count).
template <typename Protocol, typename IO>
std::size_t
deliver(Protocol &protocol, IO &io, std::string_view wire) {
    std::memcpy(io.input.allocate_back(wire.size()), wire.data(), wire.size());
    AllocScope        scope;
    const std::size_t size = protocol.getMessageSize();
    EXPECT_EQ(size, wire.size()) << "one whole message";
    if (size != 0) {
        protocol.onMessage(size);
        io.input.free_front(size);
    }
    return AllocScope::count();
}

template <typename Protocol, typename IO>
void
declared_bodies_leave_the_parser_buffer_alone(std::string const &declared_head, std::string const &chunked_head) {
    const std::size_t initial = qb::allocator::pipe<char>{}.capacity();
    const std::size_t cap     = protocol_limits::MAX_BODY_RESERVE_HINT;
    const std::string large(cap, 'a');
    // A small declared body, then one at the reserve's cap -- read after the parser's reset(), which must keep the
    // reserve off -- then a chunked body: it adopts the parser's buffer, so its capacity is what the declared bodies left.
    {
        IO       io;
        Protocol protocol(io);
        (void) deliver(protocol, io, declared_head + "5\r\n\r\nhello");
        (void) deliver(protocol, io, declared_head + std::to_string(cap) + "\r\n\r\n" + large);
        ASSERT_TRUE(io.last.has_value());
        EXPECT_EQ(io.last->body().size(), cap);
        (void) deliver(protocol, io, chunked_head + one_chunk("hello"));
        ASSERT_TRUE(io.last.has_value());
        ASSERT_EQ(io.last->body().raw().size(), 5u) << "the chunked message was delivered";
        EXPECT_EQ(io.last->body().raw().capacity(), initial) << "a declared body left a reserve in the parser's buffer";
    }
    if (!allocation_counter_is_live())
        GTEST_SKIP() << "the operator new replacement is not observing allocations on this toolchain; the capacity oracle "
                        "above ran";
    // A declared body costs the same after a chunked body, which left the parser's buffer null, as after a declared one.
    IO       warm_io;
    Protocol warm(warm_io);
    (void) deliver(warm, warm_io, chunked_head + one_chunk("warm")); // restore_body_buffer()'s one-time read, uncounted
    (void) deliver(warm, warm_io, chunked_head + one_chunk("warm"));
    IO       after_declared_io, after_chunked_io;
    Protocol after_declared(after_declared_io), after_chunked(after_chunked_io);
    (void) deliver(after_declared, after_declared_io, declared_head + "5\r\n\r\nhello");
    (void) deliver(after_chunked, after_chunked_io, chunked_head + one_chunk("hello"));
    const auto declared = deliver(after_declared, after_declared_io, declared_head + "5\r\n\r\nhello");
    const auto chunked  = deliver(after_chunked, after_chunked_io, declared_head + "5\r\n\r\nhello");
    EXPECT_EQ(chunked, declared) << "a declared body after a chunked one took a buffer it never writes";
}

TEST(ContentLengthPreallocation, TheServerReservesNothingForADeclaredBodyItCopies) {
    declared_bodies_leave_the_parser_buffer_alone<qb::protocol::http::server<server_io>, server_io>(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: ",
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n");
}

TEST(ContentLengthPreallocation, TheClientReservesNothingForADeclaredBodyItCopies) {
    declared_bodies_leave_the_parser_buffer_alone<qb::protocol::http::client<client_io>, client_io>(
        "HTTP/1.1 200 OK\r\nContent-Length: ", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
}

} // namespace

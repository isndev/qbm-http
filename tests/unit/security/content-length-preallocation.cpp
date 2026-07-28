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
 * over `msg.body().raw()` — which deallocates whatever was reserved. So the allocation was never
 * used by anything, on any path.
 *
 * Two oracles, because one of them is not available everywhere:
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
#include <new>
#include <string>

#include <gtest/gtest.h>

#include "../1.1/protocol/base.h"
#include "../http.h"

using namespace qb::http;

namespace {
std::atomic<bool>        g_counting{false};
std::atomic<std::size_t> g_bytes{0};

inline void *
tracked_alloc_nothrow(std::size_t n) noexcept {
    if (g_counting.load(std::memory_order_relaxed))
        g_bytes.fetch_add(n, std::memory_order_relaxed);
    return std::malloc(n ? n : 1);
}

inline void *
tracked_alloc(std::size_t n) {
    void *p = tracked_alloc_nothrow(n);
    if (!p)
        throw std::bad_alloc();
    return p;
}

// Aligned storage must be released by the same family, and std::free accepts
// std::aligned_alloc memory on every platform qb targets.
inline void *
tracked_alloc_aligned_nothrow(std::size_t n, std::align_val_t a) noexcept {
    const std::size_t align = static_cast<std::size_t>(a);
    // aligned_alloc requires a size that is a multiple of the alignment.
    const std::size_t size = ((n ? n : 1) + align - 1) / align * align;
    if (g_counting.load(std::memory_order_relaxed))
        g_bytes.fetch_add(size, std::memory_order_relaxed);
    return std::aligned_alloc(align, size);
}

inline void *
tracked_alloc_aligned(std::size_t n, std::align_val_t a) {
    void *p = tracked_alloc_aligned_nothrow(n, a);
    if (!p)
        throw std::bad_alloc();
    return p;
}

/// RAII arm/disarm so a throw inside the parser cannot leave counting on.
struct AllocScope {
    AllocScope() {
        g_bytes.store(0, std::memory_order_relaxed);
        g_counting.store(true, std::memory_order_relaxed);
    }
    ~AllocScope() {
        g_counting.store(false, std::memory_order_relaxed);
    }
    [[nodiscard]] static std::size_t
    bytes() {
        return g_bytes.load(std::memory_order_relaxed);
    }
};
} // namespace

// Replaced globally for this TU only. malloc/free keeps this compatible with the sanitizer
// presets (ASan intercepts malloc, so its heap bookkeeping still applies).
// The replacement set must be COMPLETE. libstdc++ reaches for `operator new(size_t, nothrow_t)`
// (std::get_temporary_buffer) and, for over-aligned types, the `align_val_t` overloads. Replacing
// only the two plain forms left those going to the sanitizer's allocator while the plain
// `operator delete` below freed them with std::free -- ASan reports alloc-dealloc-mismatch and
// aborts. Found on Linux; macOS never took the nothrow path. Every allocating form below routes
// through the tracker and is freed by a matching form.
void *
operator new(std::size_t n) {
    return tracked_alloc(n);
}
void *
operator new[](std::size_t n) {
    return tracked_alloc(n);
}
void *
operator new(std::size_t n, const std::nothrow_t &) noexcept {
    return tracked_alloc_nothrow(n);
}
void *
operator new[](std::size_t n, const std::nothrow_t &) noexcept {
    return tracked_alloc_nothrow(n);
}
void *
operator new(std::size_t n, std::align_val_t a) {
    return tracked_alloc_aligned(n, a);
}
void *
operator new[](std::size_t n, std::align_val_t a) {
    return tracked_alloc_aligned(n, a);
}
void *
operator new(std::size_t n, std::align_val_t a, const std::nothrow_t &) noexcept {
    return tracked_alloc_aligned_nothrow(n, a);
}
void *
operator new[](std::size_t n, std::align_val_t a, const std::nothrow_t &) noexcept {
    return tracked_alloc_aligned_nothrow(n, a);
}
void
operator delete(void *p) noexcept {
    std::free(p);
}
void
operator delete[](void *p) noexcept {
    std::free(p);
}
void
operator delete(void *p, std::size_t) noexcept {
    std::free(p);
}
void
operator delete[](void *p, std::size_t) noexcept {
    std::free(p);
}
void
operator delete(void *p, const std::nothrow_t &) noexcept {
    std::free(p);
}
void
operator delete[](void *p, const std::nothrow_t &) noexcept {
    std::free(p);
}
void
operator delete(void *p, std::align_val_t) noexcept {
    std::free(p);
}
void
operator delete[](void *p, std::align_val_t) noexcept {
    std::free(p);
}
void
operator delete(void *p, std::size_t, std::align_val_t) noexcept {
    std::free(p);
}
void
operator delete[](void *p, std::size_t, std::align_val_t) noexcept {
    std::free(p);
}
void
operator delete(void *p, std::align_val_t, const std::nothrow_t &) noexcept {
    std::free(p);
}
void
operator delete[](void *p, std::align_val_t, const std::nothrow_t &) noexcept {
    std::free(p);
}

namespace {

/// Heap a single request is allowed to commit before its body arrives. Generous next to the 64 KiB
/// reserve hint (the parser also allocates for headers, the message object and the URL), and three
/// orders of magnitude below the 100 MB a declared Content-Length used to buy.
constexpr std::size_t kPerRequestBudget = 1u * 1024u * 1024u;

/// Does the replaced `operator new` above actually see allocations? Under ASan it does not (the
/// sanitizer runtime intercepts first), and a counter stuck at zero would make every budget
/// assertion below pass for the wrong reason.
bool
allocation_counter_is_live() {
    // The size must be opaque and the buffer must be touched, or the compiler elides the whole
    // new/delete pair (C++14 allows it) and the probe reports a dead instrument on every build.
    static volatile std::size_t opaque = 4096;
    const std::size_t           n      = opaque;
    AllocScope                  scope;
    auto                       *p = new char[n];
    p[0] = 'x';
    p[n - 1] = 'y';
    const auto seen = AllocScope::bytes();
    volatile char sink = static_cast<char>(p[0] + p[n - 1]);
    (void) sink;
    delete[] p;
    return seen >= n;
}

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

    EXPECT_LE(huge, small + kPerRequestBudget)
        << "declaring " << protocol_limits::MAX_BODY_SIZE << " instead of 1024 cost " << (huge - small)
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

} // namespace

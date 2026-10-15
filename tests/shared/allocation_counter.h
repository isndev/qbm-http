/**
 * @file qbm/http/tests/shared/allocation_counter.h
 * @brief A replaced global `operator new` that counts the bytes allocated while an AllocScope is alive.
 *
 * Moved unchanged out of unit/security/content-length-preallocation.cpp, where it was written and
 * verified live (release and sanitize presets), so that another test binary can ask "did this
 * allocate?" with the same instrument (unit/message/headers-utility.cpp, Huly QB-1068).
 *
 * It REPLACES the global allocation functions: include it in exactly ONE translation unit of a test
 * binary, and check allocation_counter_is_live() before trusting a zero (a sanitizer runtime can
 * intercept first; under ThreadSanitizer the replacement is not even compiled, see below).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <new>

#ifdef _MSC_VER
#include <malloc.h> // _aligned_malloc / _aligned_free (see the aligned pair below)
#endif

namespace {
std::atomic<bool>        g_counting{false};
std::atomic<std::size_t> g_bytes{0};

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

// ---------------------------------------------------------------------------------------------
// ThreadSanitizer: the allocator replacement below must NOT be compiled.
//
// `libclang_rt.tsan_cxx.a(tsan_new_delete.cpp.o)` defines every global `operator new` /
// `operator delete` form as a STRONG symbol (ASan's equivalents are weak, which is why the
// `sanitize` preset links — and there the replacement even wins, so Oracle 2 stays live).
// Defining them here too is a plain ODR collision the static linker rejects outright:
//
//   ld: multiple definition of `operator new[](unsigned long)';
//       libclang_rt.tsan_cxx-aarch64.a(tsan_new_delete.cpp.o): first defined here
//
// — 20 such errors, one per replaced form. That link error is not local to this test: ninja stops
// the build, so the ENTIRE `sanitize-thread` lane failed to build on Linux, and therefore had
// never run there at all. (macOS links because the Apple TSan runtime resolves these through
// interposition rather than a strong archive definition, so the collision is Linux-only and was
// invisible here.)
//
// Compiling the replacement out — rather than excluding the test from the lane — is the right
// trade because it costs the TSan lane nothing it could ever have had: with `tsan_cxx` owning
// allocation there is no way for a replaced `operator new` to observe anything.
// `allocation_counter_is_live()` therefore returns false here and Oracle 2 self-skips, exactly as
// it already does on any toolchain that intercepts first. Oracle 1 — `body().raw().capacity()`,
// allocator-independent — is asserted BEFORE that skip, so it still runs and still pins the defect
// this file exists for; read the resulting `[ SKIPPED ]` as "Oracle 2 did not apply", not as
// "nothing was checked". Keeping the test in the lane also keeps the parser under TSan's actual
// instrumentation, which excluding the binary would forfeit.
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define QB_TEST_TSAN_ACTIVE 1
#endif
#endif
#if defined(__SANITIZE_THREAD__) // GCC spelling
#define QB_TEST_TSAN_ACTIVE 1
#endif
#ifndef QB_TEST_TSAN_ACTIVE
#define QB_TEST_TSAN_ACTIVE 0
#endif

#if !QB_TEST_TSAN_ACTIVE
namespace {
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

// Aligned storage must be released by the SAME family as it was allocated from, and there is no
// one portable pair. MSVC's UCRT deliberately ships no C11 `std::aligned_alloc`: on Windows
// `free()` cannot release an over-aligned block, so `_aligned_malloc` must be paired with
// `_aligned_free`. Elsewhere `std::free` does accept `std::aligned_alloc` memory. Both halves are
// selected together here; the aligned `operator delete` overloads below route to
// qb_aligned_free(), never to std::free().
// NOTE the argument order differs between the two (`_aligned_malloc(size, align)` vs
// `aligned_alloc(align, size)`), which is why this is a function and not a bare macro.
inline void *
qb_aligned_alloc(std::size_t align, std::size_t size) noexcept {
#ifdef _MSC_VER
    return _aligned_malloc(size, align);
#else
    return std::aligned_alloc(align, size);
#endif
}
inline void
qb_aligned_free(void *p) noexcept {
#ifdef _MSC_VER
    _aligned_free(p);
#else
    std::free(p);
#endif
}

inline void *
tracked_alloc_aligned_nothrow(std::size_t n, std::align_val_t a) noexcept {
    const std::size_t align = static_cast<std::size_t>(a);
    // aligned_alloc requires a size that is a multiple of the alignment (harmless for
    // _aligned_malloc, which does not).
    const std::size_t size = ((n ? n : 1) + align - 1) / align * align;
    if (g_counting.load(std::memory_order_relaxed))
        g_bytes.fetch_add(size, std::memory_order_relaxed);
    return qb_aligned_alloc(align, size);
}

inline void *
tracked_alloc_aligned(std::size_t n, std::align_val_t a) {
    void *p = tracked_alloc_aligned_nothrow(n, a);
    if (!p)
        throw std::bad_alloc();
    return p;
}

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
// Every ALIGNED form pairs with qb_aligned_free -- std::free here would be an
// allocator-family mismatch (heap corruption on Windows, where the aligned block carries a
// header std::free knows nothing about).
void
operator delete(void *p, std::align_val_t) noexcept {
    qb_aligned_free(p);
}
void
operator delete[](void *p, std::align_val_t) noexcept {
    qb_aligned_free(p);
}
void
operator delete(void *p, std::size_t, std::align_val_t) noexcept {
    qb_aligned_free(p);
}
void
operator delete[](void *p, std::size_t, std::align_val_t) noexcept {
    qb_aligned_free(p);
}
void
operator delete(void *p, std::align_val_t, const std::nothrow_t &) noexcept {
    qb_aligned_free(p);
}
void
operator delete[](void *p, std::align_val_t, const std::nothrow_t &) noexcept {
    qb_aligned_free(p);
}
#endif // !QB_TEST_TSAN_ACTIVE

namespace {

/// Does the replaced `operator new` actually see allocations? Under ASan it does not (the
/// sanitizer runtime intercepts first), and under TSan it is not even compiled (see
/// QB_TEST_TSAN_ACTIVE); a counter stuck at zero would make every budget assertion below pass for
/// the wrong reason.
bool
allocation_counter_is_live() {
    // The size must be opaque and the buffer must be touched, or the compiler elides the whole
    // new/delete pair (C++14 allows it) and the probe reports a dead instrument on every build.
    static volatile std::size_t opaque = 4096;
    const std::size_t           n      = opaque;
    AllocScope                  scope;
    auto                       *p = new char[n];
    p[0]                          = 'x';
    p[n - 1]                      = 'y';
    const auto    seen            = AllocScope::bytes();
    volatile char sink            = static_cast<char>(p[0] + p[n - 1]);
    (void) sink;
    delete[] p;
    return seen >= n;
}

} // namespace

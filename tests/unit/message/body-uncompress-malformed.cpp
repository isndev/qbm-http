/*
 * qb - C++ Actor Framework
 * Copyright (c) 2011-2026 qb - isndev (cpp.actor). All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * See the License for the specific terms.
 */

/**
 * @file unit/message/body-uncompress-malformed.cpp
 * @brief `Body::uncompress()` must terminate on every malformed compressed body.
 *
 * This runs on bytes an attacker fully controls: `middleware/compression.h` decompresses the
 * REQUEST body server-side, and `1.1/http.h` + `1.1/client.cpp` decompress response bodies for a
 * client talking to a hostile server.
 *
 * The decompression loop is `while (!done && i_processed != body.size())`, so it only makes
 * progress while the decompressor keeps consuming input or reports completion. A malformed stream
 * that makes zlib consume nothing, produce nothing and not finish would spin forever — and each
 * turn also calls `out.allocate_back(body.size() * 2)`, so a spin is not merely a busy loop but an
 * unbounded allocation. That would be a remote DoS on a single-threaded core.
 *
 * The zip-bomb guard on the decompressed size (`MAX_BODY_SIZE`) does not cover this: it bounds how
 * much comes OUT, and a non-progressing stream produces nothing at all.
 *
 * Coverage: every truncation point of a valid gzip stream, single-byte corruption at every offset,
 * random garbage, garbage appended to a valid stream, and the same corpus through `deflate`.
 * Termination is what is asserted — throwing counts as terminating; only spinning does not.
 * A watchdog thread bounds the whole run so a regression FAILS instead of hanging the suite.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * @ingroup Tests
 */

#include <atomic>
#include <chrono>
#include <cstddef>
#include <random>
#include <string>
#include <thread>

#include <gtest/gtest.h>
#include <qbm/http/http.h>

#ifdef QB_WITH_COMPRESSION
#include <zlib.h>

namespace {

/// A real gzip stream, so every mutation below starts from something valid.
[[nodiscard]] std::string
gzip(std::string const &plain) {
    z_stream s{};
    EXPECT_EQ(deflateInit2(&s, Z_BEST_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY), Z_OK);
    std::string out(plain.size() + 1024, '\0');
    s.next_in   = reinterpret_cast<Bytef *>(const_cast<char *>(plain.data()));
    s.avail_in  = static_cast<uInt>(plain.size());
    s.next_out  = reinterpret_cast<Bytef *>(out.data());
    s.avail_out = static_cast<uInt>(out.size());
    EXPECT_EQ(deflate(&s, Z_FINISH), Z_STREAM_END);
    out.resize(out.size() - s.avail_out);
    deflateEnd(&s);
    return out;
}

std::atomic<std::size_t> g_progress{0};   ///< bumped after every input, watched for stalls
std::atomic<bool>        g_running{true}; ///< clears when the corpus is done

/// Feed one input through the real decompression path. Throwing IS terminating.
void
feed(std::string const &bytes, std::string const &encoding) {
    try {
        qb::http::Body body;
        body.raw().put(bytes.data(), bytes.size());
        (void) body.uncompress(encoding);
    } catch (...) {
    }
    g_progress.fetch_add(1, std::memory_order_relaxed);
}

} // namespace

TEST(BodyUncompressMalformed, EveryMalformedCompressedBodyTerminates) {
    // Highly compressible, so the corpus is bomb-shaped as well as malformed.
    const std::string plain(64u * 1024u, 'A');
    const std::string valid = gzip(plain);
    ASSERT_GT(valid.size(), 32u) << "the mutation corpus needs a real multi-byte gzip stream";

    // The regression this guards against is a SPIN inside uncompress(), so the main thread would
    // never come back to check a flag — it has to be the watchdog itself that ends the process, or
    // a regression hangs the suite until the ctest timeout with nothing said about why. Aborting
    // from here turns that into a named, diagnosable failure. (Verified by injecting a spin: the
    // run dies on this message instead of hanging.)
    std::thread watchdog([&] {
        std::size_t last = 0;
        int         idle = 0;
        while (g_running.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            const auto now = g_progress.load(std::memory_order_relaxed);
            idle           = (now == last) ? idle + 1 : 0;
            last           = now;
            if (idle >= 40) { // 10 s with no input completed
                std::fprintf(stderr,
                             "\nFATAL: Body::uncompress() stopped making progress after %zu inputs.\n"
                             "A malformed stream that makes the decompressor consume no input, produce no output\n"
                             "and never report done spins in the `while (!done && i_processed != body.size())`\n"
                             "loop, re-allocating body.size() * 2 every turn. Request bodies reach this through\n"
                             "the compression middleware, so that is a remote DoS on a single-threaded core.\n",
                             now);
                std::fflush(stderr);
                std::abort();
            }
        }
    });

    // 1. Every truncation point — the shape that leaves zlib waiting for more input.
    for (std::size_t n = 0; n <= valid.size(); ++n)
        feed(valid.substr(0, n), "gzip");

    // 2. Single-byte corruption at every offset (header, deflate blocks, CRC/ISIZE trailer).
    for (std::size_t i = 0; i < valid.size(); ++i)
        for (unsigned char v : {0x00u, 0xFFu, 0x5Au}) {
            auto mutated = valid;
            mutated[i]   = static_cast<char>(v);
            feed(mutated, "gzip");
        }

    // 3. Random garbage, and garbage appended to an otherwise valid stream.
    std::mt19937                       rng{12345u};
    std::uniform_int_distribution<int> byte{0, 255};
    for (int t = 0; t < 512; ++t) {
        std::string garbage(static_cast<std::size_t>(1 + (t % 256)), '\0');
        for (auto &c : garbage)
            c = static_cast<char>(byte(rng));
        feed(garbage, "gzip");
        feed(valid + garbage, "gzip");
    }

    // 4. The same corpus routed through the deflate decompressor.
    for (std::size_t n = 0; n <= valid.size(); n += 97)
        feed(valid.substr(0, n), "deflate");

    g_running.store(false, std::memory_order_relaxed);
    watchdog.join();

    EXPECT_GT(g_progress.load(), valid.size()) << "the corpus should have run to completion";
}

/**
 * @test A genuine round-trip still works, so the corpus above is not passing on a no-op.
 */
TEST(BodyUncompressMalformed, ValidGzipStillRoundTrips) {
    const std::string plain(64u * 1024u, 'A');

    qb::http::Body body;
    const auto     compressed = gzip(plain);
    body.raw().put(compressed.data(), compressed.size());

    EXPECT_EQ(body.uncompress("gzip"), plain.size());
    EXPECT_EQ(body.as<std::string>(), plain);
}

#endif // QB_WITH_COMPRESSION

/**
 * @file qbm/http/middleware/compression.cpp
 * @brief Out-of-line definitions for HTTP compression middleware option presets.
 *
 * Hosts the non-template factory presets of `CompressionOptions`
 * (`max_compression`, `fast_compression`); the rest of the compression
 * middleware is template-based and remains header-only.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./compression.h"

#include <initializer_list>

namespace qb::http {

namespace {

// The encodings of `order` that this build registers, in that order: a list never names a codec the build cannot
// produce, and zstd / br join it only in a qb built with QB_WITH_ZSTD / QB_WITH_BROTLI (Huly QB-93).
std::vector<std::string>
registered_encodings(std::initializer_list<const char *> order) {
    std::vector<std::string> names;
#if defined(QB_HAS_COMPRESSION)
    for (const char *name : order) {
        if (qb::compression::builtin::algorithm::supported(name))
            names.emplace_back(name);
    }
#else
    (void) order;
#endif
    return names;
}

} // namespace

// The orders are measured (qb's compress-codecs bench, the Codec cases: JSON and HTML at 4 KiB, 64 KiB and 1 MiB,
// each codec at its factory level -- gzip 6, zstd 3, brotli 5 -- and a provider per stream, on MSVC and on g++-14).
// zstd compresses 1.6 to 4 times as fast as gzip at 4 KiB and 6.8 to 14 times as fast from 64 KiB, within 8 % of its
// ratio, and this middleware compresses on the loop that serves the connection; brotli's output is 0 to 17 % smaller
// than gzip's, as fast or faster from 64 KiB and up to 1.7 times slower at 4 KiB.
CompressionOptions::CompressionOptions() noexcept
    : _compress_responses(true)
    , _decompress_requests(true)
    , _min_size_to_compress(1024)
    , _preferred_encodings(registered_encodings({"zstd", "br", "gzip", "deflate"})) {}

CompressionOptions
CompressionOptions::max_compression() noexcept {
    // Smallest output first; zstd at its factory level is 2 to 8 % larger than gzip on JSON.
    return CompressionOptions().min_size_to_compress(256).preferred_encodings(registered_encodings({"br", "gzip", "deflate", "zstd"}));
}

CompressionOptions
CompressionOptions::fast_compression() noexcept {
    // Cheapest encoder first; deflate keeps its place ahead of gzip (the same zlib stream without the gzip frame).
    return CompressionOptions().min_size_to_compress(2048).preferred_encodings(registered_encodings({"zstd", "deflate", "gzip", "br"}));
}

} // namespace qb::http

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

namespace qb::http {

CompressionOptions
CompressionOptions::max_compression() noexcept {
    return CompressionOptions()
        .min_size_to_compress(256)                 // Compress smaller files
        .preferred_encodings({"gzip", "deflate"}); // "br" would need Brotli support
}

CompressionOptions
CompressionOptions::fast_compression() noexcept {
    return CompressionOptions()
        .min_size_to_compress(2048)                // Compress only larger files
        .preferred_encodings({"deflate", "gzip"}); // Deflate is often faster than gzip
}

} // namespace qb::http

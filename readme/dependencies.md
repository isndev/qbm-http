# `qbm-http`: Dependencies

This document outlines the dependencies required by the `qbm-http` module.

## Core Dependencies

*   **`qb-core`:** The HTTP module relies heavily on the core QB Actor Framework for asynchronous operations, actor integration (optional), event loops, and utilities.
    *   **`qb-io`:** Specifically, it uses `qb-io` components for:
        *   Asynchronous system (`qb::io::async`)
        *   TCP/SSL sockets (`qb::io::tcp`, `qb::io::tcp::ssl`)
        *   URI parsing (`qb::io::uri`)
        *   Stream abstractions (`qb::io::stream`)
        *   High-performance containers (`qb::allocator::pipe`, `qb::unordered_map`)
        *   Time utilities (`qb::Timestamp`)
*   **`llhttp`:** A high-performance C-based HTTP parser library. This is typically **bundled** with `qbm-http` (found in `qbm/http/not-qb/llhttp`) and linked statically, so you usually don't need to install it separately.
*   **C++17 Compiler:** Requires a compiler supporting C++17 features.
*   **CMake:** (>= 3.14) For building the module and integrating it into projects.

## Optional Dependencies

These dependencies enable extra features and must be available on the system if the corresponding CMake options are enabled during the build of `qb-io` and/or `qbm-http`.

*   **OpenSSL (`QB_IO_WITH_SSL=ON`):** Required for:
    *   HTTPS client and server functionality (`qb::http::use<...>::ssl::*`).
    *   JWT signing/verification using asymmetric algorithms (RSA, ECDSA, EdDSA) via `qb::jwt`.
    *   Most cryptographic utilities in `qb::crypto`.
*   **Zlib (`QB_IO_WITH_ZLIB=ON`):** Required for:
    *   Automatic request/response body compression and decompression (`Content-Encoding: gzip`, `Content-Encoding: deflate`).
    *   Using the `qb::compression` utilities directly.
*   **Argon2 (`QB_IO_WITH_ARGON2=ON`):** Required for Argon2 password hashing support in `qb::crypto`. (If not available, `qb::crypto` falls back to PBKDF2).

## Bundled Dependencies

These libraries are included directly within the `qb` or `qbm/http` source tree and do not need to be installed separately:

*   `llhttp`: HTTP parser.
*   `nlohmann/json`: Used for `qb::json` implementation.
*   `stduuid/uuid`: Used for `qb::uuid` implementation.
*   `ska_hash`: Used for `qb::unordered_map/set` implementations.

## Build System Integration

When using CMake, finding `qb-core` (`find_package(qb REQUIRED)`) should transitively bring in `qb-io`. Linking against `qbm::http` (`target_link_libraries(your_target PRIVATE qbm::http)`) will link the necessary components.

The bundled dependencies are typically linked automatically when building `qbm-http`.

Ensure optional dependencies like OpenSSL and Zlib are installed on your system (development headers and libraries) if you enable the corresponding `QB_IO_WITH_SSL` or `QB_IO_WITH_ZLIB` CMake options when building the main QB framework or the HTTP module directly. 
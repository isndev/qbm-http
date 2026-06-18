<!-- Verified-against: qbm-http @ qb 2.0.0 (C++20 default, C++23 supported) -->
# Contributing to qbm-http

qbm-http is a module of the qb actor framework. General contribution guidelines — branch and pull-request
flow, code style (`.clang-format` / `.clang-tidy`), the Developer Certificate of Origin sign-off, and the
Code of Conduct — follow the framework's [CONTRIBUTING guide](../../qb/CONTRIBUTING.md). Security
vulnerabilities must not be filed as public issues; see [SECURITY.md](./SECURITY.md).

This document covers what is specific to building and testing the module.

## Build and test

qbm-http is built through the qb module loader, not on its own. From a project that embeds qb:

```cmake
add_subdirectory(qb)
qb_load_modules("${CMAKE_CURRENT_SOURCE_DIR}/qbm")
target_link_libraries(your_target PRIVATE qbm::http)
```

To build and run the module's own test suite, configure the framework with tests enabled and build from the
repository root:

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DQB_BUILD_TESTS=ON -B build
cmake --build build --parallel
ctest --test-dir build --output-on-failure -R qbm-http
```

The SSL-dependent features (HTTP/2, HTTP/3, HTTPS, secure WebSocket, JWT, auth) only build when OpenSSL is
present (`QB_HAS_SSL`); HTTP/3 additionally requires QUIC and libnghttp3 (`QBM_HTTP_HAS_HTTP3`). Add a test
for any new behavior, and exercise both the SSL-enabled and SSL-disabled configurations when your change
touches a gated feature.

## Conventions

Use the `qb::http` namespace, include the umbrella header `<http/http.h>`, and express time with the
`qb::duration` / `qb::wall_time` vocabulary (cookie and middleware spans are `qb::duration`; the HTTP date
API is `qb::wall_time`; JWT NumericDate fields are `std::chrono::seconds`). Never use the removed
`qb::Timestamp` / `qb::Duration` types.

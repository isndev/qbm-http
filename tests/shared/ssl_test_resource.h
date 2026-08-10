/**
 * @file qbm/http/tests/shared/ssl_test_resource.h
 * @brief Shared SSL/TLS test-certificate locator for the qbm-http test suite.
 *
 * The qbm-http system suite drives real loopback servers over TLS (HTTPS,
 * HTTP/2 over ALPN, HTTP/3/QUIC, secure WebSocket). Those servers need a
 * server certificate + private key pair. The qb repository ships a self-signed
 * pair under @c qb/resources/ssl/{cert,key}.pem; this header provides a single,
 * reconciled lookup that finds them regardless of where the test binary is run
 * from (build tree, install tree, CWD).
 *
 * Design intent (per the system-suite contract):
 *   - The certificate is a HARD prerequisite for the secure system tests, not a
 *     soft "skip if missing". Tests/CMake should assert on @ref certs_available()
 *     and FAIL a secure build when the resources are absent, rather than silently
 *     @c GTEST_SKIP-ing coverage away. The accessors below expose both a boolean
 *     and the resolved paths so the test/CMake layer can make that call.
 *
 * Reconciled from the multiple inline copies that previously lived in:
 *   - tests/test-session-http.cpp        (find_ssl_test_resource multi-candidate)
 *   - tests/test-http3-client.cpp        (ssl_resource_path / cert_path / key_path)
 *   - tests/test-coro-http2-client.cpp   ("cert.pem"/"key.pem" literals)
 *   - tests/test-ws-session.cpp          ("cert.pem"/"key.pem" literals)
 *   - tests/system/http2/http2-client.cpp
 *   - tests/system/server/make-server-factory.cpp (check_test_certs_exist)
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#ifndef QBM_HTTP_TESTS_SHARED_SSL_TEST_RESOURCE_H
#define QBM_HTTP_TESTS_SHARED_SSL_TEST_RESOURCE_H

#include <array>
#include <filesystem>
#include <string>
#include <system_error>

namespace qb::http::test {

/**
 * @brief Resolve the on-disk path of a named SSL test resource (e.g. "cert.pem").
 *
 * Searches a fixed, ordered list of candidate locations and returns the first
 * one that exists. The repository-root candidate (qb/resources/ssl/<name>) is
 * the canonical source shipped in the qb tree; the remaining candidates cover
 * common build/install/CWD layouts so the lookup works whether the test binary
 * is launched from the build dir, an install dir, or with a working-directory
 * copy of the certs.
 *
 * The repo root is derived from this header's own location:
 *   .../qb-dev/qbm/http/tests/shared/ssl_test_resource.h
 * Four parent_path() hops land on the qb-dev workspace root, under which the qb
 * submodule lives at qb/resources/ssl/.
 *
 * @param file_name Base file name of the resource (e.g. "cert.pem", "key.pem").
 * @return The first existing candidate path, or the canonical candidate (which
 *         may not exist) when none are found — so callers always get a usable,
 *         loggable path. Use @ref certs_available() to test existence.
 */
inline std::filesystem::path
find_ssl_test_resource(const char *file_name) {
    namespace fs = std::filesystem;

    // .../qbm/http/tests/shared/<this header>  ->  workspace (qb-dev) root.
    //
    // `lexically_normal()` is LOAD-BEARING. `__FILE__` expands to the include path as WRITTEN,
    // so for a test under `system/<subdir>/` (which includes this header as
    // "../../shared/ssl_test_resource.h") it is the UNNORMALISED
    // `.../tests/system/http3/../../shared/ssl_test_resource.h`. `parent_path()` is purely
    // lexical: five of them peel the trailing components one at a time and land on
    // `.../qbm/http/tests/system` instead of the workspace root — so all three source-tree
    // candidates below pointed at `.../qbm/http/tests/system/qb/resources/ssl/…`, which never
    // exists. Resolution then depended entirely on the CWD-relative candidates, which is how an
    // intermittent `certs_available() == false` could abort the HTTP/3 system tests under a
    // parallel `ctest` run. Normalising first collapses the `..` components so the canonical
    // candidate resolves for every test, at any nesting depth, regardless of CWD.
    const fs::path repo_root = fs::path(__FILE__)
                                   .lexically_normal()
                                   .parent_path()  // shared/
                                   .parent_path()  // tests/
                                   .parent_path()  // http/
                                   .parent_path()  // qbm/
                                   .parent_path(); // qb-dev/ (workspace root)

    const fs::path cwd = fs::current_path();

    const std::array<fs::path, 7> candidates = {
        // Canonical: the certs shipped inside the qb submodule (C=FR/O=ISNDEV, no CN, no SAN).
        repo_root / "qb" / "resources" / "ssl" / file_name,
        // The qb-io system tests' own committed pair (the CN=localhost one). This candidate
        // named `qb/source/io/tests/system/resources/ssl` — the pre-3.0 layout. `qb/source`
        // has not existed since the source restructure, so the candidate could never match
        // and the list was silently one entry shorter than it reads.
        repo_root / "qb" / "tests" / "io" / "system" / "resources" / "ssl" / file_name,
        // Common CMake/Visual Studio out-of-source build output layout.
        repo_root / "out" / "build" / "x64-Release" / "bin" / "tests" / "ssl" / file_name,
        // Working-directory copies (CTest often runs from the build dir).
        cwd / file_name,
        cwd / "ssl" / file_name,
        cwd / "resources" / "ssl" / file_name,
        cwd.parent_path() / "bin" / "tests" / "ssl" / file_name,
    };

    for (const auto &candidate : candidates) {
        std::error_code ec;
        if (fs::exists(candidate, ec) && !ec) {
            return candidate;
        }
    }
    // Nothing found: return the canonical candidate so the caller has a
    // meaningful path to report in a hard-failure diagnostic.
    return candidates[0];
}

/** @brief Resolved path of the test server certificate ("cert.pem"). */
inline std::filesystem::path
ssl_cert_path() {
    return find_ssl_test_resource("cert.pem");
}

/** @brief Resolved path of the test server private key ("key.pem"). */
inline std::filesystem::path
ssl_key_path() {
    return find_ssl_test_resource("key.pem");
}

/**
 * @brief Whether BOTH the test certificate and key resolve to existing files.
 *
 * This is the predicate the system-test / CMake layer should assert on to make
 * the certificates a hard prerequisite: a missing pair means a secure build
 * cannot run its TLS coverage and should FAIL loudly rather than skip.
 *
 * @return true if cert.pem and key.pem both exist on disk.
 */
inline bool
certs_available() {
    namespace fs = std::filesystem;
    std::error_code ec_cert;
    std::error_code ec_key;
    const bool      cert_ok = fs::exists(ssl_cert_path(), ec_cert) && !ec_cert;
    const bool      key_ok  = fs::exists(ssl_key_path(), ec_key) && !ec_key;
    return cert_ok && key_ok;
}

} // namespace qb::http::test

#endif // QBM_HTTP_TESTS_SHARED_SSL_TEST_RESOURCE_H

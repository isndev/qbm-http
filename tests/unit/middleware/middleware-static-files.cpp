/**
 * @file qbm/http/tests/unit/middleware/middleware-static-files.cpp
 * @brief Unit tests for qb::http::StaticFilesMiddleware.
 *
 * Drives the real qb::http::Router<Session> synchronously over the shared
 * capturing MockMiddlewareSession against a temporary on-disk directory tree
 * (local filesystem I/O only — no daemon, no event loop, so this stays unit
 * tier). SetUp materialises a fixed tree (index.html, file1.txt, image.jpg, an
 * extension-less file, a subdir with its own index+css, empty.txt, a battery of
 * special-character filenames, an out-of-root file and two symlinks) and probes
 * two platform capabilities ONCE: symlink creation and filesystem
 * case-sensitivity.
 *
 * Coverage walks content-type/length, index serving, prefix stripping,
 * 404/403, HEAD, method passthrough, ETag / If-None-Match (incl. weak + wildcard
 * + anti-substring), Last-Modified / If-Modified-Since, conditional-GET
 * precedence, Range (partial / suffix / oversize-suffix / 416 / disabled),
 * Cache-Control, directory listing (incl. special-char + UTF-8 escaping),
 * MIME overrides, path normalisation, and a security suite (traversal,
 * percent-encoding, null-byte, symlink escape, oversize, reject-symlinks).
 *
 * The single-range `parse_byte_range` white-box cases live in their own pure
 * unit, unit/http1/range-parser.cpp.
 *
 * Capability handling (no silent green): if the platform cannot create symlinks,
 * the symlink suite hard-FAILs under CI (env `CI` set) and skips ONCE locally;
 * the case-sensitivity probe picks the single deterministic expected status.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <system_error>

#include "../../shared/middleware_test_fixture.h"

#include "../middleware/static_files.h"
#include "../routing/context.h"
#include "../routing/router.h"

using qb::http::test::MockMiddlewareSession;

namespace {

/** @brief True when running under CI (a missing OS capability must FAIL, not skip). */
[[nodiscard]] bool
running_on_ci() {
    const char *ci = std::getenv("CI");
    return ci != nullptr && ci[0] != '\0';
}

class StaticFilesMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockMiddlewareSession>                   _session;
    std::unique_ptr<qb::http::Router<MockMiddlewareSession>> _router;
    std::filesystem::path                                    _test_root_dir;
    std::filesystem::path                                    _outside_file_path;
    std::filesystem::path                                    _outside_root_file_path; ///< `<temp>/outside_root.txt`, the real escape target of the traversal tests.

    /// @brief Sentinel body that NO traversal test may ever serve (escape == bug).
    static constexpr const char *kOutsideRootSecret = "SECRET_OUTSIDE_ROOT_CONTENT";

    // --- One-shot platform capability probes (resolved in SetUp) -----------
    bool _symlinks_supported          = false; ///< OS allowed symlink creation in the temp tree.
    bool _filesystem_case_insensitive = false; ///< `/FILE1.TXT` resolves to `file1.txt` on this FS.

    void
    create_test_file(const std::filesystem::path &path, const std::string &content) {
        std::filesystem::create_directories(path.parent_path());
        std::ofstream outfile(path);
        ASSERT_TRUE(outfile.is_open()) << "Failed to open file for writing: " << path;
        outfile << content;
        outfile.close();
    }

    void
    SetUp() override {
        _session = std::make_shared<MockMiddlewareSession>();

        std::error_code ec;
        _test_root_dir     = std::filesystem::temp_directory_path(ec) / "static_files_mw_tests";
        ASSERT_FALSE(ec) << "Failed to get temp directory path: " << ec.message();
        _outside_file_path = std::filesystem::temp_directory_path(ec) / "static_files_mw_tests_OUTSIDE_FILE.txt";
        ASSERT_FALSE(ec) << "Failed to get temp directory path for outside file: " << ec.message();
        // The escape TARGET the SecurityPathTraversal* tests actually reference:
        // `/../outside_root.txt` from the root resolves to `<temp>/outside_root.txt`.
        // It MUST exist with a known sentinel body so a regressed escape guard
        // that serves the real outside file is caught (instead of silently
        // passing because the file was missing -> 404).
        _outside_root_file_path = std::filesystem::temp_directory_path(ec) / "outside_root.txt";
        ASSERT_FALSE(ec) << "Failed to get temp directory path for outside-root file: " << ec.message();

        std::filesystem::remove_all(_test_root_dir, ec);
        std::filesystem::remove(_outside_file_path, ec);
        std::filesystem::remove(_outside_root_file_path, ec);

        std::filesystem::create_directories(_test_root_dir, ec);
        ASSERT_FALSE(ec) << "Failed to create test root directory: " << _test_root_dir << " (" << ec.message() << ")";

        create_test_file(_test_root_dir / "index.html", "Root Index HTML");
        create_test_file(_test_root_dir / "file1.txt", "Contents of file1.txt");
        create_test_file(_test_root_dir / "image.jpg", "JPG_BINARY_DATA");
        create_test_file(_test_root_dir / "no_extension_file", "File without extension");
        create_test_file(_test_root_dir / "subdir" / "index.html", "Subdir Index HTML");
        create_test_file(_test_root_dir / "subdir" / "file2.css", "/* CSS content for file2 */");
        create_test_file(_test_root_dir / "empty.txt", "");
        create_test_file(_test_root_dir / "file with spaces.txt", "File with spaces in name");
        create_test_file(_test_root_dir / "file plus.txt", "File with literal space");
        create_test_file(_test_root_dir / "file+plus.txt", "File with literal plus");
        create_test_file(_test_root_dir / "file&name.html", "File with ampersand");
        create_test_file(_test_root_dir / "file'quote.txt", "File with single quote");
#ifndef _WIN32
        create_test_file(_test_root_dir / "file\"double.txt", "File with double quote");
        create_test_file(_test_root_dir / "<tag>.xml", "File with tags");
        // UTF-8 multi-byte filename for directory-listing escaping coverage
        // (POSIX native path encoding is UTF-8; skipped on Windows where the
        // narrow path encoding differs and would mangle the byte sequence).
        create_test_file(_test_root_dir / std::filesystem::path(std::string("caf\xC3\xA9.txt")), "UTF-8 named file");
#endif

        create_test_file(_outside_file_path, "Contents of file outside root");
        create_test_file(_outside_root_file_path, kOutsideRootSecret);

        // --- Symlink capability probe (ONCE) -------------------------------
        std::error_code symlink_ec;
        std::filesystem::create_symlink(_outside_file_path, _test_root_dir / "symlink_to_outside.txt", symlink_ec);
        _symlinks_supported = !symlink_ec;
        if (_symlinks_supported) {
            std::filesystem::create_symlink(_test_root_dir / "file1.txt", _test_root_dir / "symlink_to_inside.txt", symlink_ec);
            _symlinks_supported = !symlink_ec;
        }

        _test_root_dir = std::filesystem::canonical(_test_root_dir, ec);
        ASSERT_FALSE(ec) << "Failed to get canonical path for test root: " << ec.message();

        // --- Case-sensitivity probe (ONCE) ---------------------------------
        // file1.txt definitely exists; does an upper-cased lookup resolve to it?
        std::error_code probe_ec;
        _filesystem_case_insensitive = std::filesystem::exists(_test_root_dir / "FILE1.TXT", probe_ec) && !probe_ec;
    }

    void
    TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(_test_root_dir, ec);
        std::filesystem::remove(_outside_file_path, ec);
        std::filesystem::remove(_outside_root_file_path, ec);
    }

    /** @brief Skip-once-locally / FAIL-on-CI guard for the symlink suite. */
    void
    require_symlinks_or_resolve(const char *what) {
        if (_symlinks_supported) {
            return;
        }
        if (running_on_ci()) {
            FAIL() << "Symlink creation is unavailable but required on CI for: " << what
                   << " — the path-escape defence cannot be left untested.";
        } else {
            GTEST_SKIP() << "Platform did not allow symlink creation; skipping locally: " << what;
        }
    }

    qb::http::Request
    create_request(qb::http::method method = qb::http::method::GET, const std::string &target_path = "/",
                   const std::map<std::string, std::string> &headers_map = {}) {
        qb::http::Request req;
        req.method() = method;
        try {
            req.uri() = qb::io::uri("http://localhost" + target_path);
        } catch (const std::exception &e) {
            ADD_FAILURE() << "URI parse failure: " << target_path << " (" << e.what() << ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        for (const auto &header_pair : headers_map) {
            req.set_header(header_pair.first, header_pair.second);
        }
        req.major_version = 1;
        req.minor_version = 1;
        return req;
    }

    /// @brief A traversal attempt must be DENIED, and must NEVER serve the real
    /// outside-root file. FORBIDDEN/NOT_FOUND is the pass case; if the middleware
    /// answered OK the served body MUST NOT be the outside-root sentinel (which
    /// would mean the escape guard let the request out of the root).
    void
    expect_traversal_denied() {
        const auto st = _session->_response.status();
        EXPECT_TRUE(st == qb::http::status::FORBIDDEN || st == qb::http::status::NOT_FOUND)
            << "Status was: " << st;
        if (st == qb::http::status::FORBIDDEN) {
            EXPECT_EQ(_session->_response.body().as<std::string>(), "Forbidden");
        }
        if (st == qb::http::status::OK) {
            EXPECT_NE(_session->_response.body().as<std::string>(), kOutsideRootSecret)
                << "Path traversal escaped the root and served outside_root.txt!";
        }
        EXPECT_FALSE(_session->_final_handler_called);
    }

    qb::http::RouteHandlerFn<MockMiddlewareSession>
    dummy_final_handler() {
        return [this](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
            if (_session)
                _session->_final_handler_called = true;
            // Reaching this means the middleware did NOT serve/short-circuit.
            ctx->response().status() = qb::http::status::NOT_IMPLEMENTED;
            ctx->response().body()   = "Dummy final handler reached - middleware did not complete.";
            ctx->complete();
        };
    }

    qb::http::RouteHandlerFn<MockMiddlewareSession>
    passthrough_expectant_handler() {
        return [this](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
            if (_session)
                _session->_final_handler_called = true;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Passthrough handler reached.";
            ctx->complete();
        };
    }

    void
    configure_router_and_run(std::shared_ptr<qb::http::StaticFilesMiddleware<MockMiddlewareSession>> sf_mw, qb::http::Request request,
                             bool expect_middleware_to_complete = true) {
        _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
        _router->use(sf_mw);
        if (expect_middleware_to_complete) {
            _router->get("/*catch_all", dummy_final_handler());
        } else {
            _router->get(std::string(request.uri().path()), passthrough_expectant_handler());
        }
        _router->compile();
        _session->reset();
        _router->route(_session, std::move(request));
    }

    std::shared_ptr<qb::http::StaticFilesMiddleware<MockMiddlewareSession>>
    make_mw(const qb::http::StaticFilesOptions &options) {
        return qb::http::static_files_middleware<MockMiddlewareSession>(options);
    }
};

// --- Basic serving ---------------------------------------------------------

TEST_F(StaticFilesMiddlewareTest, ServeTextFile) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/file1.txt"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Contents of file1.txt");
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/plain; charset=utf-8");
    EXPECT_EQ(std::string(_session->_response.header("Content-Length")), std::to_string(std::string("Contents of file1.txt").length()));
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, NormalGetAdvertisesAcceptRanges) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true); // default, but pin it
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/file1.txt"));

    // A plain 200 with ranges enabled must advertise Accept-Ranges: bytes.
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Accept-Ranges")), "bytes");
}

TEST_F(StaticFilesMiddlewareTest, PathDecodePreservesLiteralPlus) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto                         sf_mw = make_mw(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file+plus.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "File with literal plus");

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file%2Bplus.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "File with literal plus");

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file%20plus.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "File with literal space");
}

TEST_F(StaticFilesMiddlewareTest, ServeImageFile) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/image.jpg"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "image/jpeg");
    EXPECT_EQ(_session->_response.body().as<std::string>(), "JPG_BINARY_DATA");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, ServeRootIndexHtml) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Root Index HTML");
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/html; charset=utf-8");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, ServeSubdirIndexHtml) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/subdir/"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Subdir Index HTML");
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/html; charset=utf-8");
    EXPECT_FALSE(_session->_final_handler_called);
}

// --- Prefix stripping ------------------------------------------------------

TEST_F(StaticFilesMiddlewareTest, PathPrefixStripping) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_path_prefix_to_strip("/static_assets");
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/static_assets/file1.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Contents of file1.txt");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, PathPrefixNotMatchingContinue) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_path_prefix_to_strip("/static_assets");
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/other_path/file1.txt"), false);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Passthrough handler reached.");
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, PathPrefixRequiresSegmentBoundary) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_path_prefix_to_strip("/static");
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/static_assets/file1.txt"), false);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Passthrough handler reached.");
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, PathPrefixToEmptyServesRootIndex) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_path_prefix_to_strip("/static");
    options.with_serve_index_file(true);
    auto sf_mw = make_mw(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/static/"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Root Index HTML");

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/static"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Root Index HTML");
}

// --- Not found / methods ---------------------------------------------------

TEST_F(StaticFilesMiddlewareTest, FileNotFound) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/nonexistent.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_FOUND);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "File not found");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, HeadRequest) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::HEAD, "/file1.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.body().empty());
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/plain; charset=utf-8");
    EXPECT_EQ(std::string(_session->_response.header("Content-Length")), std::to_string(std::string("Contents of file1.txt").length()));
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, NonGetHeadMethodsPassThrough) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto                         sf_mw = make_mw(options);

    _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
    _router->use(sf_mw);
    _router->post("/file1.txt", passthrough_expectant_handler());
    _router->compile();
    _session->reset();
    _router->route(_session, create_request(qb::http::method::POST, "/file1.txt"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Passthrough handler reached.");
    EXPECT_TRUE(_session->_final_handler_called);
}

// --- Conditional GET -------------------------------------------------------

TEST_F(StaticFilesMiddlewareTest, ETagAndIfNoneMatch) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_etags(true);
    auto sf_mw = make_mw(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    const std::string etag = std::string(_session->_response.header("ETag"));
    EXPECT_FALSE(etag.empty());

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt", {{"If-None-Match", etag}}));
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_MODIFIED);
    EXPECT_TRUE(_session->_response.body().empty());
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, IfNoneMatchDoesNotUseSubstringMatching) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_etags(true);
    auto sf_mw = make_mw(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt"));
    ASSERT_EQ(_session->_response.status(), qb::http::status::OK);
    const std::string etag = std::string(_session->_response.header("ETag"));
    ASSERT_FALSE(etag.empty());

    const std::string misleading = "\"prefix-" + etag.substr(1, etag.size() - 2) + "-suffix\"";
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt", {{"If-None-Match", misleading}}));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Contents of file1.txt");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, IfNoneMatchSupportsWeakComparisonAndWildcard) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_etags(true);
    auto sf_mw = make_mw(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt"));
    ASSERT_EQ(_session->_response.status(), qb::http::status::OK);
    const std::string etag = std::string(_session->_response.header("ETag"));
    ASSERT_FALSE(etag.empty());

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt", {{"If-None-Match", "W/" + etag}}));
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_MODIFIED);
    EXPECT_TRUE(_session->_response.body().empty());

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt", {{"If-None-Match", "*"}}));
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_MODIFIED);
    EXPECT_TRUE(_session->_response.body().empty());
}

TEST_F(StaticFilesMiddlewareTest, LastModifiedAndIfModifiedSince) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_last_modified(true);
    auto sf_mw = make_mw(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    const std::string last_modified = std::string(_session->_response.header("Last-Modified"));
    EXPECT_FALSE(last_modified.empty());

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt", {{"If-Modified-Since", last_modified}}));
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_MODIFIED);
    EXPECT_TRUE(_session->_response.body().empty());
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, MatchingETagWinsWhenBothValidatorsPresent) {
    // With a matching If-None-Match AND an If-Modified-Since, the ETag validator
    // is evaluated first and short-circuits to 304 (RFC 7232 §6 precedence).
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_etags(true).with_last_modified(true);
    auto sf_mw = make_mw(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt"));
    ASSERT_EQ(_session->_response.status(), qb::http::status::OK);
    const std::string etag          = std::string(_session->_response.header("ETag"));
    const std::string last_modified = std::string(_session->_response.header("Last-Modified"));
    ASSERT_FALSE(etag.empty());
    ASSERT_FALSE(last_modified.empty());

    // Pair a MATCHING ETag with a deliberately ancient If-Modified-Since (which on
    // its own would force a 200) — the matching ETag must still yield 304.
    configure_router_and_run(
        sf_mw, create_request(qb::http::method::GET, "/file1.txt",
                              {{"If-None-Match", etag}, {"If-Modified-Since", "Sat, 01 Jan 2000 00:00:00 GMT"}}));
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_MODIFIED);
    EXPECT_TRUE(_session->_response.body().empty());
}

// --- Range requests --------------------------------------------------------

TEST_F(StaticFilesMiddlewareTest, RangeRequestPartialContent) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true);
    const std::string file_content = "Contents of file1.txt";

    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/file1.txt", {{"Range", "bytes=9-14"}}));

    EXPECT_EQ(_session->_response.status(), qb::http::status::PARTIAL_CONTENT);
    EXPECT_EQ(_session->_response.body().as<std::string>(), file_content.substr(9, 6));
    EXPECT_EQ(std::string(_session->_response.header("Content-Range")), "bytes 9-14/" + std::to_string(file_content.length()));
    EXPECT_EQ(std::string(_session->_response.header("Content-Length")), "6");
    EXPECT_EQ(std::string(_session->_response.header("Accept-Ranges")), "bytes");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, RangeRequestSuffix) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true);
    const std::string file_content = "Contents of file1.txt";

    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/file1.txt", {{"Range", "bytes=-4"}}));

    EXPECT_EQ(_session->_response.status(), qb::http::status::PARTIAL_CONTENT);
    EXPECT_EQ(_session->_response.body().as<std::string>(), file_content.substr(file_content.length() - 4, 4));
    EXPECT_EQ(std::string(_session->_response.header("Content-Range")),
              "bytes " + std::to_string(file_content.length() - 4) + "-" + std::to_string(file_content.length() - 1) + "/"
                  + std::to_string(file_content.length()));
    EXPECT_EQ(std::string(_session->_response.header("Content-Length")), "4");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, RangeRequestSuffixLargerThanFileServesWholeRepresentation) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true);
    const std::string file_content = "Contents of file1.txt";

    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/file1.txt", {{"Range", "bytes=-9999"}}));

    ASSERT_EQ(_session->_response.status(), qb::http::status::PARTIAL_CONTENT);
    EXPECT_EQ(_session->_response.body().as<std::string>(), file_content);
    EXPECT_EQ(std::string(_session->_response.header("Content-Range")),
              "bytes 0-" + std::to_string(file_content.length() - 1) + "/" + std::to_string(file_content.length()));
    EXPECT_EQ(std::string(_session->_response.header("Content-Length")), std::to_string(file_content.length()));
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, RangeRequestUnsatisfiableYields416) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true);
    const std::string file_content = "Contents of file1.txt";

    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/file1.txt", {{"Range", "bytes=1000-2000"}}));

    EXPECT_EQ(_session->_response.status(), qb::http::status::RANGE_NOT_SATISFIABLE);
    EXPECT_EQ(std::string(_session->_response.header("Content-Range")), "bytes */" + std::to_string(file_content.length()));
    EXPECT_TRUE(_session->_response.body().empty());
    EXPECT_FALSE(_session->_final_handler_called);
}

// Malformed Range header variants all map to a single 416 outcome at the HTTP
// seam. The single-range parse rules themselves are pinned white-box in
// unit/http1/range-parser.cpp; here we only assert the integration outcome.
class StaticFilesMalformedRangeTest : public StaticFilesMiddlewareTest, public ::testing::WithParamInterface<std::string> {};

TEST_P(StaticFilesMalformedRangeTest, YieldsRangeNotSatisfiable) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true);
    const std::string file_content = "Contents of file1.txt";

    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/file1.txt", {{"Range", GetParam()}}));

    EXPECT_EQ(_session->_response.status(), qb::http::status::RANGE_NOT_SATISFIABLE) << "Range: " << GetParam();
    EXPECT_TRUE(_session->_response.body().empty());
    EXPECT_EQ(std::string(_session->_response.header("Content-Range")), "bytes */" + std::to_string(file_content.length()));
    EXPECT_FALSE(_session->_final_handler_called);
}

INSTANTIATE_TEST_SUITE_P(MalformedRanges, StaticFilesMalformedRangeTest,
                         ::testing::Values("bytes=", "bytes=abc-def", "bytes=10-5", "bytes=0-5, 10-15"));

TEST_F(StaticFilesMiddlewareTest, RangeRequestDisabledServesFullContent) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(false);
    const std::string file_content = "Contents of file1.txt";

    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/file1.txt", {{"Range", "bytes=9-14"}}));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), file_content);
    EXPECT_EQ(std::string(_session->_response.header("Content-Length")), std::to_string(file_content.length()));
    EXPECT_TRUE(_session->_response.header("Content-Range").empty());
    EXPECT_TRUE(_session->_response.header("Accept-Ranges").empty());
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, IfRangeHeaderIsIgnoredAndRangeStillServed) {
    // The middleware does not implement If-Range; a Range request must still be
    // honoured (206) regardless of any If-Range value. Pins the current contract.
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true).with_etags(true);
    const std::string file_content = "Contents of file1.txt";

    configure_router_and_run(make_mw(options),
                             create_request(qb::http::method::GET, "/file1.txt",
                                            {{"Range", "bytes=0-3"}, {"If-Range", "\"some-stale-etag\""}}));

    EXPECT_EQ(_session->_response.status(), qb::http::status::PARTIAL_CONTENT);
    EXPECT_EQ(_session->_response.body().as<std::string>(), file_content.substr(0, 4));
    EXPECT_EQ(std::string(_session->_response.header("Content-Length")), "4");
}

// --- Cache-Control ---------------------------------------------------------

TEST_F(StaticFilesMiddlewareTest, CacheControlCustomValue) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_cache_control(true, "public, max-age=86400");
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/file1.txt"));
    EXPECT_EQ(std::string(_session->_response.header("Cache-Control")), "public, max-age=86400");
}

TEST_F(StaticFilesMiddlewareTest, CacheControlDisabled) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_cache_control(false);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/file1.txt"));
    EXPECT_TRUE(_session->_response.header("Cache-Control").empty());
}

// --- Directory listing -----------------------------------------------------

TEST_F(StaticFilesMiddlewareTest, DirectoryListingEnabled) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_directory_listing(true).with_serve_index_file(false);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/html; charset=utf-8");
    const std::string body = _session->_response.body().as<std::string>();
    EXPECT_NE(body.find("<a href=\"/subdir/\">subdir/</a>"), std::string::npos);
    EXPECT_NE(body.find("<a href=\"/file1.txt\">file1.txt</a>"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, DirectoryListingSubdir) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_directory_listing(true).with_serve_index_file(false);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/subdir/"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/html; charset=utf-8");
    const std::string body = _session->_response.body().as<std::string>();
    EXPECT_NE(body.find("<a href=\"/subdir/file2.css\">file2.css</a>"), std::string::npos) << body;
    EXPECT_NE(body.find("<a href=\"/subdir/index.html\">index.html</a>"), std::string::npos) << body;
    EXPECT_NE(body.find("<h1>Index of subdir</h1>"), std::string::npos) << body;
    EXPECT_NE(body.find("<a href=\"../\">../</a>"), std::string::npos) << body;
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, DirectoryListingWithSpecialCharsInFilenames) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_directory_listing(true).with_serve_index_file(false);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    const std::string body = _session->_response.body().as<std::string>();

    EXPECT_NE(body.find("<a href=\"/file%20with%20spaces.txt\">file with spaces.txt</a>"), std::string::npos) << body;
    EXPECT_NE(body.find("<a href=\"/file%26name.html\">file&amp;name.html</a>"), std::string::npos) << body;
    EXPECT_NE(body.find("<a href=\"/file%27quote.txt\">file&#39;quote.txt</a>"), std::string::npos) << body;
#ifndef _WIN32
    EXPECT_NE(body.find("<a href=\"/file%22double.txt\">file&quot;double.txt</a>"), std::string::npos) << body;
    EXPECT_NE(body.find("<a href=\"/%3Ctag%3E.xml\">&lt;tag&gt;.xml</a>"), std::string::npos) << body;
#endif
}

#ifndef _WIN32
TEST_F(StaticFilesMiddlewareTest, DirectoryListingEncodesUtf8Filename) {
    // "café.txt" => UTF-8 bytes 0xC3 0xA9 for 'é'; the href must percent-encode
    // each byte (%C3%A9) while the display text keeps the literal UTF-8.
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_directory_listing(true).with_serve_index_file(false);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    const std::string body = _session->_response.body().as<std::string>();
    EXPECT_NE(body.find("<a href=\"/caf%C3%A9.txt\">caf\xC3\xA9.txt</a>"), std::string::npos) << body;
}
#endif

TEST_F(StaticFilesMiddlewareTest, DirectoryListingDisabledServeIndexFalse) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_directory_listing(false).with_serve_index_file(false);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Directory listing not allowed.");
    EXPECT_FALSE(_session->_final_handler_called);
}

// --- Misc serving ----------------------------------------------------------

TEST_F(StaticFilesMiddlewareTest, ServeEmptyFile) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/empty.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "");
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/plain; charset=utf-8");
    EXPECT_EQ(std::string(_session->_response.header("Content-Length")), "0");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, DefaultMimeTypeForUnknownExtension) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_default_mime_type("application/x-custom-unknown");
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/no_extension_file"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "application/x-custom-unknown");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, MimeTypeOverride) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.add_mime_type(".txt", "text/custom-text-type");
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/file1.txt"));
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/custom-text-type");
}

TEST_F(StaticFilesMiddlewareTest, CaseSensitiveResolutionIsDeterministicPerFilesystem) {
    // Deterministic via the one-shot case-sensitivity probe: the expected status
    // is fixed per platform, never a never-fail 200-or-404 union.
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/FILE1.TXT"));

    if (_filesystem_case_insensitive) {
        EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
        EXPECT_EQ(_session->_response.body().as<std::string>(), "Contents of file1.txt");
    } else {
        EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_FOUND);
    }
}

// --- Path normalisation ----------------------------------------------------

TEST_F(StaticFilesMiddlewareTest, PathNormalizationLeadingSlashes) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "//file1.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Contents of file1.txt");
}

TEST_F(StaticFilesMiddlewareTest, PathNormalizationInternalSlashes) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/subdir//file2.css"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "/* CSS content for file2 */");
}

TEST_F(StaticFilesMiddlewareTest, PathNormalizationDotSegment) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/./file1.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Contents of file1.txt");
}

// --- Security: traversal ---------------------------------------------------
//
// Each of these must be DENIED. The exact denial code (403 vs 404) can vary by
// where the canonicalisation rejects the path, so the union is intentional for
// the "must be denied" cases — but a simple `/../x` is pinned to 403.

TEST_F(StaticFilesMiddlewareTest, DirectoryTraversalAttemptIsForbidden) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/../some_other_file.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Forbidden");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, SecurityPathTraversalSimple) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/../outside_root.txt"));
    expect_traversal_denied();
}

TEST_F(StaticFilesMiddlewareTest, SecurityPathTraversalWithPathPrefix) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_path_prefix_to_strip("/static");
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/static/../outside_root.txt"));
    expect_traversal_denied();
}

TEST_F(StaticFilesMiddlewareTest, SecurityPathTraversalDeep) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/subdir/../../../outside_root.txt"));
    expect_traversal_denied();
}

TEST_F(StaticFilesMiddlewareTest, SecurityPathTraversalEncodedDotDotSlash) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/..%2Foutside_root.txt"));
    expect_traversal_denied();
}

TEST_F(StaticFilesMiddlewareTest, SecurityPathTraversalEncodedDotDotBackslash) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/..%5Coutside_root.txt"));
    expect_traversal_denied();
}

TEST_F(StaticFilesMiddlewareTest, SecurityPathTraversalDoubleEncodedSlash) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/..%252Foutside_root.txt"));
    expect_traversal_denied();
}

TEST_F(StaticFilesMiddlewareTest, EncodedTraversalIsRejected) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/%2e%2e%2f%2e%2e%2fetc%2fpasswd"));
    EXPECT_TRUE(_session->_response.status() == qb::http::status::FORBIDDEN || _session->_response.status() == qb::http::status::NOT_FOUND)
        << "Status was " << _session->_response.status();
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, SecurityPathNullByteInjection) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/file1.txt%00other.txt"));
    EXPECT_TRUE(_session->_response.status() == qb::http::status::NOT_FOUND || _session->_response.status() == qb::http::status::BAD_REQUEST
                || _session->_response.status() == qb::http::status::FORBIDDEN);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, SecurityAbsolutePathLikeAttempt) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto                         sf_mw = make_mw(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/C:/Windows/System32/calc.exe"));
    EXPECT_TRUE(_session->_response.status() == qb::http::status::FORBIDDEN || _session->_response.status() == qb::http::status::NOT_FOUND);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "//attacker_server/share/data.txt"));
    EXPECT_TRUE(_session->_response.status() == qb::http::status::FORBIDDEN || _session->_response.status() == qb::http::status::NOT_FOUND);
}

TEST_F(StaticFilesMiddlewareTest, SecurityLongInBoundsPathYieldsNotFound) {
    // A long but well-formed, in-bounds nonexistent path resolves cleanly to
    // "no such file": weakly_canonical succeeds and the existence check fails,
    // giving a deterministic 404 — never a security rejection.
    //
    // The path must be long in TOTAL yet keep every component under the
    // filesystem's per-component limit (POSIX NAME_MAX, 255 on Linux/macOS).
    // A single 512-char segment is NOT in-bounds: weakly_canonical fails with
    // ENAMETOOLONG, the resolver returns an empty path, and the middleware
    // (correctly) treats an unresolvable path as 403 FORBIDDEN — see the
    // companion assertion below. So the in-bounds path is built from several
    // sub-NAME_MAX (200-char) segments instead.
    qb::http::StaticFilesOptions options(_test_root_dir);

    const std::string seg(200, 'a'); // < NAME_MAX(255), so each component resolves
    const std::string long_in_bounds = "/" + seg + "/" + seg + "/" + seg + ".txt";
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, long_in_bounds));

    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_FOUND)
        << "An in-bounds path naming no file must be 404, not a security code. Status was "
        << _session->_response.status();
    EXPECT_FALSE(_session->_final_handler_called);

    // Boundary companion: a single component OVER NAME_MAX cannot be
    // canonicalised, so the resolver returns empty and the middleware rejects
    // it as FORBIDDEN (an unresolvable path is treated as a traversal/escape,
    // not a missing file). This pins the over-limit side of the boundary.
    const std::string over_name_max(512, 'a');
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/" + over_name_max + ".txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN)
        << "An un-canonicalisable (over-NAME_MAX) path must be 403, not 404. Status was "
        << _session->_response.status();
    EXPECT_FALSE(_session->_final_handler_called);
}

// --- Security: symlinks (capability-gated, never silently green) ------------

TEST_F(StaticFilesMiddlewareTest, SecuritySymlinkToOutsideRootIsForbidden) {
    require_symlinks_or_resolve("symlink-escape-is-denied");

    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/symlink_to_outside.txt"));
    EXPECT_TRUE(_session->_response.status() == qb::http::status::FORBIDDEN || _session->_response.status() == qb::http::status::NOT_FOUND)
        << "Status code was: " << _session->_response.status();
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, SecuritySymlinkToInsideRootIsOk) {
    require_symlinks_or_resolve("inside-symlink-is-served");

    qb::http::StaticFilesOptions options(_test_root_dir);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/symlink_to_inside.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK) << "Body: " << _session->_response.body().as<std::string>();
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Contents of file1.txt");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, RejectSymlinksOptionBlocksInsideLinks) {
    require_symlinks_or_resolve("reject-symlinks-blocks-inside-link");

    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_reject_symlinks(true);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/symlink_to_inside.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_FALSE(_session->_final_handler_called);
}

// --- DoS guard: max_file_size ----------------------------------------------

TEST_F(StaticFilesMiddlewareTest, MaxFileSizeRejectsLargeFiles) {
    create_test_file(_test_root_dir / "big.bin", std::string(2048, 'x'));
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_max_file_size(1024);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/big.bin"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::PAYLOAD_TOO_LARGE);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, MaxFileSizeZeroDisablesCap) {
    create_test_file(_test_root_dir / "huge.bin", std::string(4096, 'y'));
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_max_file_size(0);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/huge.bin"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().size(), 4096u);
}

// A Range request against an oversize file still hits the whole-file DoS cap
// (which dominates: the per-range cap can only fire when full_file_size already
// exceeds the budget, so the full-file guard returns first). Pins that Range +
// max_file_size interact safely.
TEST_F(StaticFilesMiddlewareTest, RangeRequestAgainstOversizeFileYields413) {
    create_test_file(_test_root_dir / "big.bin", std::string(4096, 'z'));
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true).with_max_file_size(16);
    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/big.bin", {{"Range", "bytes=0-1023"}}));
    EXPECT_EQ(_session->_response.status(), qb::http::status::PAYLOAD_TOO_LARGE);
}

// --- Constructor guards ----------------------------------------------------

TEST_F(StaticFilesMiddlewareTest, ConstructorRejectsEmptyRootDirectory) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.root_directory.clear();
    EXPECT_THROW((qb::http::StaticFilesMiddleware<MockMiddlewareSession>(options)), std::invalid_argument);
}

TEST_F(StaticFilesMiddlewareTest, ConstructorRejectsNonexistentRootDirectory) {
    qb::http::StaticFilesOptions options(_test_root_dir / "does_not_exist_subdir_xyz");
    EXPECT_THROW((qb::http::StaticFilesMiddleware<MockMiddlewareSession>(options)), std::runtime_error);
}

// --- Fluent option setters not otherwise exercised -------------------------

TEST_F(StaticFilesMiddlewareTest, WithRootDirectoryAndIndexFileNameSettersServeNamedIndex) {
    create_test_file(_test_root_dir / "main.page", "Custom Index Page");

    // Build options against a throw-away path, then re-root via with_root_directory
    // and pick a non-default index file name via with_index_file_name.
    qb::http::StaticFilesOptions options(std::filesystem::temp_directory_path());
    options.with_root_directory(_test_root_dir).with_serve_index_file(true).with_index_file_name("main.page");

    configure_router_and_run(make_mw(options), create_request(qb::http::method::GET, "/"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Custom Index Page");
}

// --- cancel() is a no-op on the synchronous middleware ---------------------

TEST_F(StaticFilesMiddlewareTest, CancelIsNoop) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto                         mw = make_mw(options);
    EXPECT_NO_THROW(mw->cancel());
}

} // namespace

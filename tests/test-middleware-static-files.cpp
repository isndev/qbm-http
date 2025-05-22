#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/static_files.h" // The StaticFilesMiddleware
#include "../routing/router.h"       // For qb::http::Router
#include "../routing/context.h"      // For qb::http::Context

#include <memory>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <system_error>
#include <map>

// --- Mock Session for StaticFilesMiddleware Tests ---
struct MockStaticFilesSession {
    qb::http::Response _response;
    std::string _session_id_str = "static_files_test_session";
    bool _final_handler_called = false; // To check if middleware completed or continued

    qb::http::Response &get_response_ref() { return _response; }

    MockStaticFilesSession &operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    void reset() {
        _response = qb::http::Response();
        _final_handler_called = false;
    }
};

// --- Test Fixture for StaticFilesMiddleware ---
class StaticFilesMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockStaticFilesSession> _session;
    std::unique_ptr<qb::http::Router<MockStaticFilesSession> > _router;
    std::filesystem::path _test_root_dir;
    std::filesystem::path _outside_file_path; // For symlink tests

    // Helper to create directory structure and files
    void create_test_file(const std::filesystem::path &path, const std::string &content) {
        std::filesystem::create_directories(path.parent_path());
        std::ofstream outfile(path);
        ASSERT_TRUE(outfile.is_open()) << "Failed to open file for writing: " << path;
        outfile << content;
        outfile.close();
    }

    void SetUp() override {
        _session = std::make_shared<MockStaticFilesSession>();

        // Create a unique temporary directory for test files
        std::error_code ec;
        _test_root_dir = std::filesystem::temp_directory_path(ec) / "static_files_mw_tests";
        ASSERT_FALSE(ec) << "Failed to get temp directory path: " << ec.message();

        _outside_file_path = std::filesystem::temp_directory_path(ec) / "static_files_mw_tests_OUTSIDE_FILE.txt";
        ASSERT_FALSE(ec) << "Failed to get temp directory path for outside file: " << ec.message();

        std::filesystem::remove_all(_test_root_dir, ec); // Clean up if exists from previous failed run
        std::filesystem::remove(_outside_file_path, ec); // Clean up outside file too
        // Don't assert on remove_all's ec, as it might not exist.

        std::filesystem::create_directories(_test_root_dir, ec);
        ASSERT_FALSE(ec) << "Failed to create test root directory: " << _test_root_dir << " (" << ec.message() << ")";

        // Create test files and directories
        create_test_file(_test_root_dir / "index.html", "Root Index HTML");
        create_test_file(_test_root_dir / "file1.txt", "Contents of file1.txt");
        create_test_file(_test_root_dir / "image.jpg", "JPG_BINARY_DATA"); // Placeholder
        create_test_file(_test_root_dir / "no_extension_file", "File without extension");
        create_test_file(_test_root_dir / "subdir" / "index.html", "Subdir Index HTML");
        create_test_file(_test_root_dir / "subdir" / "file2.css", "/* CSS content for file2 */");
        create_test_file(_test_root_dir / "empty.txt", "");
        // Files for special character tests in directory listing
        create_test_file(_test_root_dir / "file with spaces.txt", "File with spaces in name");
        create_test_file(_test_root_dir / "file&name.html", "File with ampersand");
        create_test_file(_test_root_dir / "file'quote.txt", "File with single quote");
        create_test_file(_test_root_dir / "file\"double.txt", "File with double quote");
        create_test_file(_test_root_dir / "<tag>.xml", "File with tags");

        // Create the file outside the root for symlink testing
        create_test_file(_outside_file_path, "Contents of file outside root");

        // Create symlinks for testing (platform-dependent)
        // Symlink pointing outside
        std::error_code symlink_ec;
        std::filesystem::create_symlink(_outside_file_path, _test_root_dir / "symlink_to_outside.txt", symlink_ec);
        if (symlink_ec) {
            std::cerr << "[WARNING] Could not create symlink_to_outside.txt: " << symlink_ec.message()
                    << ". Symlink security tests might be skipped or ineffective." << std::endl;
        }
        // Symlink pointing inside (legitimate use)
        std::filesystem::create_symlink(_test_root_dir / "file1.txt", _test_root_dir / "symlink_to_inside.txt",
                                        symlink_ec);
        if (symlink_ec) {
            std::cerr << "[WARNING] Could not create symlink_to_inside.txt: " << symlink_ec.message()
                    << ". Symlink tests might be affected." << std::endl;
        }

        // Make root dir canonical for consistent comparisons
        _test_root_dir = std::filesystem::canonical(_test_root_dir, ec);
        ASSERT_FALSE(ec) << "Failed to get canonical path for test root: " << ec.message();
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(_test_root_dir, ec);
        // Don't assert here, just best effort cleanup.
        if (ec) {
            std::cerr << "Warning: Failed to remove test directory " << _test_root_dir << ": " << ec.message() <<
                    std::endl;
        }
        std::filesystem::remove(_outside_file_path, ec); // Clean up outside file
        if (ec) {
            std::cerr << "Warning: Failed to remove outside file " << _outside_file_path << ": " << ec.message() <<
                    std::endl;
        }
    }

    qb::http::Request create_request(
        qb::http::method method = qb::http::method::GET,
        const std::string &target_path = "/",
        const std::map<std::string, std::string> &headers_map = {}
    ) {
        qb::http::Request req;
        req.method() = method;
        try {
            req.uri() = qb::io::uri("http://localhost" + target_path);
        } catch (const std::exception &e) {
            ADD_FAILURE() << "URI parse failure: " << target_path << " (" << e.what() << ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        for (const auto &header_pair: headers_map) {
            req.set_header(header_pair.first, header_pair.second);
        }
        return req;
    }

    // Dummy handler to attach to routes if middleware is expected to complete the request
    qb::http::RouteHandlerFn<MockStaticFilesSession> dummy_final_handler() {
        return [this](std::shared_ptr<qb::http::Context<MockStaticFilesSession> > ctx) {
            if (_session) _session->_final_handler_called = true;
            // This handler should ideally not be called if StaticFilesMiddleware serves a file.
            ctx->response().status() = qb::http::status::NOT_IMPLEMENTED; // Should not happen
            ctx->response().body() = "Dummy final handler reached - indicates middleware did not complete.";
            ctx->complete();
        };
    }

    // Handler that expects middleware to pass through
    qb::http::RouteHandlerFn<MockStaticFilesSession> passthrough_expectant_handler() {
        return [this](std::shared_ptr<qb::http::Context<MockStaticFilesSession> > ctx) {
            if (_session) _session->_final_handler_called = true;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "Passthrough handler reached.";
            ctx->complete();
        };
    }


    void configure_router_and_run(
        std::shared_ptr<qb::http::StaticFilesMiddleware<MockStaticFilesSession> > sf_mw,
        qb::http::Request request,
        bool expect_middleware_to_complete = true
        // if true, uses dummy_final_handler, else passthrough_expectant_handler
    ) {
        _router = std::make_unique<qb::http::Router<MockStaticFilesSession> >();
        _router->use(sf_mw); // Apply middleware globally for these tests

        // Add a catch-all route for testing passthrough
        // The path for this route should not conflict with valid static file paths normally.
        // Or, ensure that sf_mw calls "continue" for paths it doesn't handle.
        if (expect_middleware_to_complete) {
            _router->get("/*catch_all", dummy_final_handler());
        } else {
            // For passthrough, the specific path of the request is used for the route definition.
            // This ensures that the router can match it if the static files middleware continues.
            _router->get(std::string(request.uri().path()), passthrough_expectant_handler());
        }


        _router->compile();
        _session->reset();
        _router->route(_session, std::move(request));
    }
};

// --- Test Cases ---

TEST_F(StaticFilesMiddlewareTest, ServeTextFile) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Contents of file1.txt");
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/plain; charset=utf-8");
    EXPECT_EQ(std::string(_session->_response.header("Content-Length")),
              std::to_string(std::string("Contents of file1.txt").length()));
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, ServeImageFile) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/image.jpg"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "image/jpeg");
    EXPECT_EQ(_session->_response.body().as<std::string>(), "JPG_BINARY_DATA");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, ServeRootIndexHtml) {
    qb::http::StaticFilesOptions options(_test_root_dir); // serve_index_file is true by default
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Root Index HTML");
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/html; charset=utf-8");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, ServeSubdirIndexHtml) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/subdir/"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Subdir Index HTML");
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/html; charset=utf-8");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, PathPrefixStripping) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_path_prefix_to_strip("/static_assets");
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/static_assets/file1.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Contents of file1.txt");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, PathPrefixNotMatchingContinue) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_path_prefix_to_strip("/static_assets");
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    // Request path does not match the strip prefix
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/other_path/file1.txt"), false);

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK); // Handled by passthrough_expectant_handler
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Passthrough handler reached.");
    EXPECT_TRUE(_session->_final_handler_called);
}


TEST_F(StaticFilesMiddlewareTest, FileNotFound) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/nonexistent.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_FOUND);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "File not found");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, DirectoryTraversalAttempt) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/../some_other_file.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN); // Or 404 depending on sanitize logic
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Forbidden");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, HeadRequest) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::HEAD, "/file1.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.body().empty());
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/plain; charset=utf-8");
    EXPECT_EQ(std::string(_session->_response.header("Content-Length")),
              std::to_string(std::string("Contents of file1.txt").length()));
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, ETagAndIfNoneMatch) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_etags(true);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    // First request to get ETag
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    std::string etag = std::string(_session->_response.header("ETag"));
    EXPECT_FALSE(etag.empty());

    // Second request with If-None-Match
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt", {{"If-None-Match", etag}}));
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_MODIFIED);
    EXPECT_TRUE(_session->_response.body().empty());
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, LastModifiedAndIfModifiedSince) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_last_modified(true);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    // First request to get Last-Modified
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    std::string last_modified = std::string(_session->_response.header("Last-Modified"));
    EXPECT_FALSE(last_modified.empty());

    // Second request with If-Modified-Since (using the exact Last-Modified value)
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt",
                                                   {{"If-Modified-Since", last_modified}}));
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_MODIFIED);
    EXPECT_TRUE(_session->_response.body().empty());
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, RangeRequestPartialContent) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);
    std::string file_content = "Contents of file1.txt"; // Expected content

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt", {{"Range", "bytes=9-14"}}));

    EXPECT_EQ(_session->_response.status(), qb::http::status::PARTIAL_CONTENT);
    EXPECT_EQ(_session->_response.body().as<std::string>(), file_content.substr(9, 6));
    EXPECT_EQ(std::string(_session->_response.header("Content-Range")),
              "bytes 9-14/" + std::to_string(file_content.length()));
    EXPECT_EQ(std::string(_session->_response.header("Content-Length")), "6");
    EXPECT_EQ(std::string(_session->_response.header("Accept-Ranges")), "bytes");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, RangeRequestSuffix) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);
    std::string file_content = "Contents of file1.txt";

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt", {{"Range", "bytes=-4"}}));

    EXPECT_EQ(_session->_response.status(), qb::http::status::PARTIAL_CONTENT);
    EXPECT_EQ(_session->_response.body().as<std::string>(), file_content.substr(file_content.length() - 4, 4));
    EXPECT_EQ(std::string(_session->_response.header("Content-Range")),
              "bytes " + std::to_string(file_content.length() - 4) + "-" + std::to_string(file_content.length() - 1) +
              "/" + std::to_string(file_content.length()));
    EXPECT_EQ(std::string(_session->_response.header("Content-Length")), "4");
    EXPECT_FALSE(_session->_final_handler_called);
}


TEST_F(StaticFilesMiddlewareTest, RangeRequestInvalid) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);
    std::string file_content = "Contents of file1.txt";

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt",
                                                   {{"Range", "bytes=1000-2000"}}));

    EXPECT_EQ(_session->_response.status(), qb::http::status::RANGE_NOT_SATISFIABLE);
    EXPECT_EQ(std::string(_session->_response.header("Content-Range")),
              "bytes */" + std::to_string(file_content.length()));
    EXPECT_TRUE(_session->_response.body().empty());
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, DirectoryListingEnabled) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_directory_listing(true);
    options.with_serve_index_file(false); // Disable index serving to force listing
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/html; charset=utf-8");
    std::string body = _session->_response.body().as<std::string>();
    // Links in directory listing for root (request_uri_path = "/") should be absolute from root
    EXPECT_NE(body.find("<a href=\"/subdir/\">subdir/</a>"), std::string::npos);
    EXPECT_NE(body.find("<a href=\"/file1.txt\">file1.txt</a>"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, DirectoryListingSubdir) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_directory_listing(true);
    options.with_serve_index_file(false); // Disable index serving to force listing for the subdir itself
    // (though subdir/index.html exists, we want to list subdir)
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    // To list /subdir/, we request /subdir/. If subdir/index.html is served, this test would fail.
    // Forcing listing means even if subdir/index.html exists, if serve_index_file is false for the dir itself,
    // it should list. This is a bit tricky. The current logic is: if serve_index_file is true, it serves it.
    // If false, OR if true but index not found, THEN it considers listing.
    // So serve_index_file=false is key here.
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/subdir/"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/html; charset=utf-8");
    std::string body = _session->_response.body().as<std::string>();

    // Links within /subdir/ listing should be relative to /subdir/
    // generate_directory_listing_html uses request_uri_path (/subdir/) as base_link_path.
    // So, file2.css becomes /subdir/file2.css
    EXPECT_NE(body.find("<a href=\"/subdir/file2.css\">file2.css</a>"), std::string::npos) << "Body: " << body;
    EXPECT_NE(body.find("<a href=\"/subdir/index.html\">index.html</a>"), std::string::npos) << "Body: " << body;
    EXPECT_NE(body.find("<h1>Index of subdir</h1>"), std::string::npos) << "Body: " << body;
    // Check for parent link
    EXPECT_NE(body.find("<a href=\"../\">../</a>"), std::string::npos) << "Body: " << body;
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, DirectoryListingDisabledServeIndexFalse) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_directory_listing(false);
    options.with_serve_index_file(false);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::FORBIDDEN);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Directory listing not allowed.");
    EXPECT_FALSE(_session->_final_handler_called);
}


TEST_F(StaticFilesMiddlewareTest, ServeEmptyFile) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/empty.txt"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "");
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/plain; charset=utf-8");
    EXPECT_EQ(std::string(_session->_response.header("Content-Length")), "0");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, DefaultMimeTypeForUnknownExtension) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_default_mime_type("application/x-custom-unknown");
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/no_extension_file"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "application/x-custom-unknown");
    EXPECT_FALSE(_session->_final_handler_called);
}

// --- New Test Cases Start Here ---

// 1. Malformed Range Headers & Multiple Ranges (Not Supported)
TEST_F(StaticFilesMiddlewareTest, RangeRequestMalformed_EmptyValue) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);
    std::string file_content = "Contents of file1.txt";

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt", {{"Range", "bytes="}}));
    // Malformed

    // Expect 416 as parse_byte_range will return nullopt, and we now treat all such failures as 416.
    EXPECT_EQ(_session->_response.status(), qb::http::status::RANGE_NOT_SATISFIABLE);
    EXPECT_TRUE(_session->_response.body().empty());
    EXPECT_EQ(std::string(_session->_response.header("Content-Range")),
              "bytes */" + std::to_string(file_content.length()));
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, RangeRequestMalformed_InvalidChars) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);
    std::string file_content = "Contents of file1.txt";

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt", {{"Range", "bytes=abc-def"}}));

    EXPECT_EQ(_session->_response.status(), qb::http::status::RANGE_NOT_SATISFIABLE);
    EXPECT_TRUE(_session->_response.body().empty());
    EXPECT_EQ(std::string(_session->_response.header("Content-Range")),
              "bytes */" + std::to_string(file_content.length()));
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, RangeRequestMalformed_StartGreaterThanEnd) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);
    std::string file_content = "Contents of file1.txt";

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt", {{"Range", "bytes=10-5"}}));

    EXPECT_EQ(_session->_response.status(), qb::http::status::RANGE_NOT_SATISFIABLE);
    EXPECT_TRUE(_session->_response.body().empty());
    EXPECT_EQ(std::string(_session->_response.header("Content-Range")),
              "bytes */" + std::to_string(file_content.length()));
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, RangeRequestMultipleRanges_NotSupported) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(true);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);
    std::string file_content = "Contents of file1.txt";

    configure_router_and_run(
        sf_mw, create_request(qb::http::method::GET, "/file1.txt", {{"Range", "bytes=0-5, 10-15"}})); // Multiple ranges

    // parse_byte_range currently fails to parse this as a single valid range, leading to 416.
    EXPECT_EQ(_session->_response.status(), qb::http::status::RANGE_NOT_SATISFIABLE);
    EXPECT_TRUE(_session->_response.body().empty());
    EXPECT_EQ(std::string(_session->_response.header("Content-Range")),
              "bytes */" + std::to_string(file_content.length()));
    EXPECT_FALSE(_session->_final_handler_called);
}

// 2. Cache-Control Specifics
TEST_F(StaticFilesMiddlewareTest, CacheControlCustomValue) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_cache_control(true, "public, max-age=86400");
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt"));
    EXPECT_EQ(std::string(_session->_response.header("Cache-Control")), "public, max-age=86400");
}

TEST_F(StaticFilesMiddlewareTest, CacheControlDisabled) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_cache_control(false);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt"));
    EXPECT_TRUE(_session->_response.header("Cache-Control").empty());
}

// 3. Directory Listing with Special Characters
TEST_F(StaticFilesMiddlewareTest, DirectoryListingWithSpecialCharsInFilenames) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_directory_listing(true).with_serve_index_file(false);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    std::string body = _session->_response.body().as<std::string>();

    // Check for URI encoded and HTML escaped filenames
    // "file with spaces.txt" -> URI: file%20with%20spaces.txt, HTML: file with spaces.txt
    EXPECT_NE(body.find("<a href=\"/file%20with%20spaces.txt\">file with spaces.txt</a>"), std::string::npos) << body;
    // "file&name.html" -> URI: file%26name.html, HTML: file&amp;name.html
    EXPECT_NE(body.find("<a href=\"/file%26name.html\">file&amp;name.html</a>"), std::string::npos) << body;
    // "file'quote.txt" -> URI: file%27quote.txt, HTML: file&#39;quote.txt
    EXPECT_NE(body.find("<a href=\"/file%27quote.txt\">file&#39;quote.txt</a>"), std::string::npos) << body;
    // "file\"double.txt" -> URI: file%22double.txt, HTML: file&quot;double.txt
    EXPECT_NE(body.find("<a href=\"/file%22double.txt\">file&quot;double.txt</a>"), std::string::npos) << body;
    // "<tag>.xml" -> URI: %3Ctag%3E.xml, HTML: &lt;tag&gt;.xml
    EXPECT_NE(body.find("<a href=\"/%3Ctag%3E.xml\">&lt;tag&gt;.xml</a>"), std::string::npos) << body;
}

// 4. Path Prefix leading to Empty Relative Path
TEST_F(StaticFilesMiddlewareTest, PathPrefixToEmptyServesRootIndex) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_path_prefix_to_strip("/static");
    options.with_serve_index_file(true);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    // Requesting exactly the prefix
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/static/"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Root Index HTML");

    _session->reset();
    // Requesting prefix without trailing slash (should also work if path normalization handles it)
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/static"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Root Index HTML");
}

// 5. Case Sensitivity (Illustrative)
TEST_F(StaticFilesMiddlewareTest, CaseInsensitiveFileSystemResolution) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    // This test's success depends on the underlying filesystem being case-insensitive (common on Win/macOS)
    // On case-sensitive filesystems (common on Linux), this would be a 404.
    // The middleware uses weakly_canonical, which should resolve if possible.
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/FILE1.TXT"));

    std::error_code ec;
    bool file_exists_case_sensitive = std::filesystem::exists(_test_root_dir / "FILE1.TXT", ec);
    bool file_exists_original_case = std::filesystem::exists(_test_root_dir / "file1.txt", ec);

    if (!file_exists_case_sensitive && file_exists_original_case) {
        // Likely case-sensitive FS where FILE1.TXT doesn't exist as such
        EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_FOUND);
        std::cout <<
                "[ INFO     ] CaseInsensitiveFileSystemResolution: FS is case-sensitive, 404 for /FILE1.TXT is expected."
                << std::endl;
    } else {
        // Case-insensitive FS or FILE1.TXT actually exists with that casing
        EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
        EXPECT_EQ(_session->_response.body().as<std::string>(), "Contents of file1.txt");
        std::cout <<
                "[ INFO     ] CaseInsensitiveFileSystemResolution: FS is case-insensitive or file exists as /FILE1.TXT, 200 OK is expected."
                << std::endl;
    }
}

// 6. MIME Type Overrides
TEST_F(StaticFilesMiddlewareTest, MimeTypeOverride) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.add_mime_type(".txt", "text/custom-text-type");
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt"));
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "text/custom-text-type");
}

// 7. Path Normalization with Complex Inputs
TEST_F(StaticFilesMiddlewareTest, PathNormalizationLeadingSlashes) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "//file1.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Contents of file1.txt");
}

TEST_F(StaticFilesMiddlewareTest, PathNormalizationInternalSlashes) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/subdir//file2.css"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "/* CSS content for file2 */");
}

TEST_F(StaticFilesMiddlewareTest, PathNormalizationDotSegment) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/./file1.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Contents of file1.txt");
}

// 8. Range Requests Disabled
TEST_F(StaticFilesMiddlewareTest, RangeRequestDisabledServesFullContent) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_range_requests(false); // Disable range requests
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);
    std::string file_content = "Contents of file1.txt";

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt", {{"Range", "bytes=9-14"}}));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), file_content);
    EXPECT_EQ(std::string(_session->_response.header("Content-Length")), std::to_string(file_content.length()));
    EXPECT_TRUE(_session->_response.header("Content-Range").empty());
    EXPECT_TRUE(_session->_response.header("Accept-Ranges").empty()); // Should not advertise if disabled
    EXPECT_FALSE(_session->_final_handler_called);
}

// --- Security Focused Tests ---

TEST_F(StaticFilesMiddlewareTest, SecurityPathTraversalSimple) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/../outside_root.txt"));
    EXPECT_NE(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.status() == qb::http::status::FORBIDDEN ||
        _session->_response.status() == qb::http::status::NOT_FOUND);
    if (_session->_response.status() == qb::http::status::FORBIDDEN) {
        EXPECT_EQ(_session->_response.body().as<std::string>(), "Forbidden");
    }
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, SecurityPathTraversalWithPathPrefix) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    options.with_path_prefix_to_strip("/static");
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    // Request path will be "/../outside_root.txt" after prefix stripping
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/static/../outside_root.txt"));
    EXPECT_NE(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.status() == qb::http::status::FORBIDDEN ||
        _session->_response.status() == qb::http::status::NOT_FOUND);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, SecurityPathTraversalDeep) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/subdir/../../../outside_root.txt"));
    EXPECT_NE(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.status() == qb::http::status::FORBIDDEN ||
        _session->_response.status() == qb::http::status::NOT_FOUND);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, SecurityPathTraversalEncodedDotDotSlash) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    // %2F is / after URI decoding. Path becomes /../outside_root.txt
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/..%2Foutside_root.txt"));
    EXPECT_NE(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.status() == qb::http::status::FORBIDDEN ||
        _session->_response.status() == qb::http::status::NOT_FOUND);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, SecurityPathTraversalEncodedDotDotBackslash) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    // %5C is \ after URI decoding. Path becomes /..\outside_root.txt which std::filesystem::path normalizes.
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/..%5Coutside_root.txt"));
    EXPECT_NE(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.status() == qb::http::status::FORBIDDEN ||
        _session->_response.status() == qb::http::status::NOT_FOUND);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, SecurityPathTraversalDoubleEncodedSlash) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    // %252F becomes %2F after first URI decode, then / after second (if any) or by path normalization.
    // qb::io::uri will decode %25 to %. So path is /..%2Foutside_root.txt -> /../outside_root.txt
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/..%252Foutside_root.txt"));
    EXPECT_NE(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.status() == qb::http::status::FORBIDDEN ||
        _session->_response.status() == qb::http::status::NOT_FOUND);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, SecurityPathNullByteInjection) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    // qb::io::uri's path parsing and std::string_view/std::filesystem::path should handle null bytes correctly
    // (i.e., not truncate early).
    // The URI parser might reject %00 or treat it as part of the name.
    // If path becomes "/file1.txt\0other.txt", filesystem will likely fail to find it.
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/file1.txt%00other.txt"));
    EXPECT_NE(_session->_response.status(), qb::http::status::OK);
    // Expect 404 because "file1.txt\0other.txt" won't be found, or 400 if URI parser rejects %00.
    EXPECT_TRUE(_session->_response.status() == qb::http::status::NOT_FOUND ||
        _session->_response.status() == qb::http::status::BAD_REQUEST ||
        _session->_response.status() == qb::http::status::FORBIDDEN);
    EXPECT_FALSE(_session->_final_handler_called);
}

// Symlink Security Tests
TEST_F(StaticFilesMiddlewareTest, SecuritySymlinkToOutsideRootIsForbidden) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    // Check if symlink was created, otherwise test is moot
    std::error_code ec;
    if (!std::filesystem::exists(_test_root_dir / "symlink_to_outside.txt", ec) && !std::filesystem::is_symlink(
            _test_root_dir / "symlink_to_outside.txt", ec)) {
        GTEST_SKIP() << "Skipping symlink test: symlink_to_outside.txt does not exist or failed to create.";
    }

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/symlink_to_outside.txt"));
    EXPECT_NE(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.status() == qb::http::status::FORBIDDEN ||
        _session->_response.status() == qb::http::status::NOT_FOUND)
        << "Status code was: " << _session->_response.status();
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(StaticFilesMiddlewareTest, SecuritySymlinkToInsideRootIsOk) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    std::error_code ec;
    if (!std::filesystem::exists(_test_root_dir / "symlink_to_inside.txt", ec) && !std::filesystem::is_symlink(
            _test_root_dir / "symlink_to_inside.txt", ec)) {
        GTEST_SKIP() << "Skipping symlink test: symlink_to_inside.txt does not exist or failed to create.";
    }

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/symlink_to_inside.txt"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK)
        << "Body: " << _session->_response.body().as<std::string>();
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Contents of file1.txt");
    EXPECT_FALSE(_session->_final_handler_called);
}

// Test for attempts to use absolute-like paths that should be caught by sanitization
TEST_F(StaticFilesMiddlewareTest, SecurityAbsolutePathLikeAttempt) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    // These paths, even if they somehow bypassed initial URI parsing stages that might clean them,
    // should be handled by sanitize_and_resolve_path to stay within the root or be rejected.
    // The key is that sanitize_and_resolve_path prepends the root_directory to the processed relative part.

    // Attempt with a path that looks like a Windows drive letter path
    // sanitize_and_resolve_path will effectively try to serve _test_root_dir / "C:/Windows/System32/calc.exe"
    // which will then be canonicalized and checked.
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "/C:/Windows/System32/calc.exe"));
    EXPECT_NE(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.status() == qb::http::status::FORBIDDEN ||
        _session->_response.status() == qb::http::status::NOT_FOUND);

    _session->reset();
    // Attempt with a path that looks like a UNC path (after http://localhost part)
    // Request will be http://localhost//attacker_server/share/data.txt
    // uri().path() will be "//attacker_server/share/data.txt"
    // sanitize_and_resolve_path will process this to "attacker_server/share/data.txt" relative to root.
    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, "//attacker_server/share/data.txt"));
    EXPECT_NE(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_response.status() == qb::http::status::FORBIDDEN ||
        _session->_response.status() == qb::http::status::NOT_FOUND);
}

TEST_F(StaticFilesMiddlewareTest, SecurityMaxPathLength) {
    qb::http::StaticFilesOptions options(_test_root_dir);
    auto sf_mw = qb::http::static_files_middleware<MockStaticFilesSession>(options);

    std::string very_long_segment(250, 'a');
    std::string long_path = "/";
    for (int i = 0; i < 10; ++i) {
        // Create a path like /aaaa.../aaaa.../ ... (10 segments)
        long_path += very_long_segment;
        if (i < 9) {
            long_path += "/";
        }
    }
    long_path += "/file.txt"; // Total length can exceed typical OS limits (e.g. > 260*10 chars)

    // We don't expect to create this file, just that the request is handled gracefully.
    // The most likely outcome is 404 because the path won't exist and can't be created.
    // Or, if the path is so long it causes issues in std::filesystem itself before existence check,
    // then potentially a 500 if not caught, but ideally still a 404 or 400/414 from URI parsing.
    // std::filesystem operations on very long paths that don't exist usually fail gracefully.

    configure_router_and_run(sf_mw, create_request(qb::http::method::GET, long_path));
    EXPECT_NE(_session->_response.status(), qb::http::status::OK);
    // Likely 404, but could be 400 (Bad Request) if URI parsing has issues, or 414 (URI Too Long) from a server layer.
    // For this middleware specifically, 404 or 403 (if somehow resolved outside root) are primary concerns.
    EXPECT_TRUE(_session->_response.status() == qb::http::status::NOT_FOUND ||
        _session->_response.status() == qb::http::status::BAD_REQUEST ||
        _session->_response.status() == qb::http::status::URI_TOO_LONG ||
        _session->_response.status() == qb::http::status::FORBIDDEN ||
        _session->_response.status() == qb::http::status::INTERNAL_SERVER_ERROR);
    // Last resort for unexpected fs errors

    // We primarily want to ensure it didn't somehow succeed.
    EXPECT_FALSE(_session->_final_handler_called && _session->_response.status() == qb::http::status::OK);
}

// --- End of New Test Cases ---

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

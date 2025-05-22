#include <gtest/gtest.h>
#include "../http.h" // Should provide Router, Request, Response, Context, etc.
#include "../middleware/compression.h" // The adapted CompressionMiddleware
#include "../routing/middleware.h" // For MiddlewareTask if needed for direct use

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <sstream> // For ostringstream in session mock

// --- Mock Session for CompressionMiddleware Tests ---
struct MockCompressionSession {
    qb::http::Response _response;
    std::string _session_id_str = "compression_test_session";
    std::ostringstream _trace; // For optional tracing if needed by handlers
    bool _final_handler_called = false;
    std::map<std::string, std::string> _response_headers_before_compression_hook;

    qb::http::Response &get_response_ref() { return _response; }

    MockCompressionSession &operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    void reset() {
        _response = qb::http::Response();
        _trace.str("");
        _trace.clear();
        _final_handler_called = false;
        _response_headers_before_compression_hook.clear();
    }
};

// --- Test Fixture for CompressionMiddleware --- 
class CompressionMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockCompressionSession> _session;
    std::unique_ptr<qb::http::Router<MockCompressionSession> > _router;
    // TaskExecutor might not be needed if CompressionMiddleware is fully sync in its process(),
    // but its response compression hook runs later in the lifecycle.

    void SetUp() override {
        _session = std::make_shared<MockCompressionSession>();
        _router = std::make_unique<qb::http::Router<MockCompressionSession> >();
    }

    qb::http::Request create_request(qb::http::method method_val = qb::http::method::GET,
                                     const std::string &target_path = "/test",
                                     const std::string &body_content = "",
                                     const std::string &content_encoding = "") {
        qb::http::Request req;
        req.method() = method_val;
        try {
            req.uri() = qb::io::uri(target_path);
        } catch (const std::exception &e) {
            ADD_FAILURE() << "URI parse failure: " << target_path << " (" << e.what() << ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        if (!body_content.empty()) {
            req.body() = body_content;
            req.set_header("Content-Length", std::to_string(body_content.length()));
        }
        if (!content_encoding.empty()) {
            req.set_header("Content-Encoding", content_encoding);
        }
        return req;
    }

    // Handler that sets a response to be potentially compressed
    qb::http::RouteHandlerFn<MockCompressionSession> success_handler(const std::string &response_body,
                                                                     const std::string &content_type = "text/plain") {
        return [this, response_body, content_type](std::shared_ptr<qb::http::Context<MockCompressionSession> > ctx) {
            _session->_final_handler_called = true;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Type", content_type);
            ctx->response().body() = response_body;
            // Content-Length will be set by router/server or by compression middleware if body changes

            // Capture headers *before* compression hook might run
            for (const auto &hdr: ctx->response().headers()) {
                if (!hdr.second.empty()) {
                    _session->_response_headers_before_compression_hook[std::string(hdr.first)] = std::string(
                        hdr.second[0]);
                }
            }
            ctx->complete();
        };
    }

    void configure_router_with_mw(std::shared_ptr<qb::http::IMiddleware<MockCompressionSession> > mw) {
        _router->use(mw);
        _router->post("/test", success_handler("Default test response body")); // POST for requests with body
        _router->get("/test", success_handler("Default test response body")); // GET for responses to compress
        _router->compile();
    }

    void make_request(qb::http::Request request) {
        _session->reset();
        _router->route(_session, std::move(request));
        // CompressionMiddleware's handle is sync, but compression hook is async (lifecycle)
        // The router->route call will trigger the full lifecycle including hooks.
    }

    // Helper to simulate gzipping data (simplified, actual zlib needed for real compression)
    // For tests, we might rely on Body::compress if it uses zlib, or mock.
    // This is a HACK for testing content_encoding header logic if real zlib isn't easily mockable here.
    std::string mock_gzip(const std::string &input) {
        // Prepend a pseudo-gzip header and append a pseudo-footer
        // This is NOT real gzip, just to make it different for tests.
        if (input.empty()) return "";
        return "gzip_header_" + input + "_gzip_footer";
    }

    std::string mock_ungzip(const std::string &input) {
        if (input.rfind("gzip_header_", 0) == 0 && input.length() > (
                sizeof("gzip_header_") - 1 + sizeof("_gzip_footer") - 1) &&
            input.substr(input.length() - (sizeof("_gzip_footer") - 1)) == "_gzip_footer") {
            return input.substr(sizeof("gzip_header_") - 1,
                                input.length() - (sizeof("gzip_header_") - 1) - (sizeof("_gzip_footer") - 1));
        }
        throw std::runtime_error("Invalid mock gzip data for ungzip");
    }
};

#ifdef QB_IO_WITH_ZLIB // Most compression tests will only run if ZLIB is enabled

TEST_F(CompressionMiddlewareTest, DecompressesGzipRequest) {
    auto comp_mw = qb::http::compression_middleware<MockCompressionSession>();
    configure_router_with_mw(comp_mw);

    std::string original_body = "This is test data for gzip.";
    std::string compressed_body;

    qb::http::Body temp_body_compress;
    temp_body_compress = original_body;
    temp_body_compress.compress("gzip"); // Use actual Body::compress
    compressed_body = temp_body_compress.as<std::string>();
    ASSERT_NE(original_body, compressed_body);

    auto req = create_request(qb::http::method::POST, "/test", compressed_body, "gzip");

    // The middleware should decompress the request body before it reaches the handler.
    // We modify the success_handler to check the request body it receives.
    _router = std::make_unique<qb::http::Router<MockCompressionSession> >(); // Reset router to add new handler
    _router->use(comp_mw);
    _router->post("/test", [this, original_body](auto ctx) {
        _session->_final_handler_called = true;
        EXPECT_EQ(ctx->request().body().template as<std::string>(), original_body);
        EXPECT_FALSE(ctx->request().has_header("Content-Encoding")); // Should be removed
        // Content-Length should be updated to decompressed size if it was present
        if (ctx->request().has_header("Content-Length")) {
            EXPECT_EQ(ctx->request().header("Content-Length"), std::to_string(original_body.length()));
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();
    make_request(std::move(req));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(CompressionMiddlewareTest, HandlesInvalidCompressedData) {
    qb::http::CompressionOptions opts;
    opts.decompress_requests(true);
    auto comp_mw = qb::http::compression_middleware<MockCompressionSession>(opts);
    configure_router_with_mw(comp_mw);

    auto req = create_request(qb::http::method::POST, "/test", "not_actually_gzipped_data", "gzip");
    make_request(std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_NE(_session->_response.body().as<std::string>().find("Invalid compressed request body"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(CompressionMiddlewareTest, CompressesResponseGzip) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(10); // Ensure our body is compressed
    auto comp_mw = qb::http::compression_middleware<MockCompressionSession>(opts);

    std::string original_response_body = "This is a response body that should be gzipped.";
    _router = std::make_unique<qb::http::Router<MockCompressionSession> >();
    _router->use(comp_mw);
    _router->get("/test", success_handler(original_response_body));
    _router->compile();

    auto req = create_request(qb::http::method::GET, "/test");
    req.set_header("Accept-Encoding", "gzip, deflate");
    make_request(std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.header("Content-Encoding"), "gzip");
    EXPECT_EQ(_session->_response.header("Vary"), "Accept-Encoding");

    qb::http::Body temp_body_decompress;
    temp_body_decompress = _session->_response.body().as<std::string>();
    temp_body_decompress.uncompress("gzip"); // Use actual Body::uncompress
    EXPECT_EQ(temp_body_decompress.as<std::string>(), original_response_body);
    EXPECT_EQ(_session->_response.header("Content-Length"), std::to_string(_session->_response.body().size()));
}

TEST_F(CompressionMiddlewareTest, DoesNotCompressSmallResponses) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(1000);
    auto comp_mw = qb::http::compression_middleware<MockCompressionSession>(opts);
    configure_router_with_mw(comp_mw);

    std::string small_body = "Small body.";
    _router->get("/small", success_handler(small_body)); // Re-add route after mw
    _router->compile();

    auto req = create_request(qb::http::method::GET, "/small");
    req.set_header("Accept-Encoding", "gzip");
    make_request(std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_FALSE(_session->_response.has_header("Content-Encoding"));
    EXPECT_EQ(_session->_response.body().as<std::string>(), small_body);
}

TEST_F(CompressionMiddlewareTest, SkipsAlreadyCompressedContentTypes) {
    auto comp_mw = qb::http::compression_middleware<MockCompressionSession>();
    configure_router_with_mw(comp_mw);

    std::string jpeg_body = "some_jpeg_data_long_enough_to_compress";
    _router->get("/image.jpg", success_handler(jpeg_body, "image/jpeg"));
    _router->compile();

    auto req = create_request(qb::http::method::GET, "/image.jpg");
    req.set_header("Accept-Encoding", "gzip");
    make_request(std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_FALSE(_session->_response.has_header("Content-Encoding"));
    EXPECT_EQ(_session->_response.body().as<std::string>(), jpeg_body);
}

TEST_F(CompressionMiddlewareTest, SkipsCompressionWhenOptionDisabled) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(false);
    auto comp_mw = qb::http::compression_middleware<MockCompressionSession>(opts);
    configure_router_with_mw(comp_mw);

    std::string body_content = "This normally would compress.";
    _router->get("/no_compress", success_handler(body_content));
    _router->compile();

    auto req = create_request(qb::http::method::GET, "/no_compress");
    req.set_header("Accept-Encoding", "gzip");
    make_request(std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_FALSE(_session->_response.has_header("Content-Encoding"));
}

TEST_F(CompressionMiddlewareTest, SkipsDecompressionWhenOptionDisabled) {
    qb::http::CompressionOptions opts;
    opts.decompress_requests(false);
    auto comp_mw = qb::http::compression_middleware<MockCompressionSession>(opts);

    std::string original_body = "This is test data for gzip.";
    std::string compressed_body;
    qb::http::Body temp_body_compress;
    temp_body_compress = original_body;
    temp_body_compress.compress("gzip");
    compressed_body = temp_body_compress.as<std::string>();

    _router = std::make_unique<qb::http::Router<MockCompressionSession> >(); // Reset router to add new handler
    _router->use(comp_mw);
    _router->post("/test_no_decompress", [this, compressed_body](auto ctx) {
        _session->_final_handler_called = true;
        EXPECT_EQ(ctx->request().body().template as<std::string>(), compressed_body); // Should receive compressed
        EXPECT_TRUE(ctx->request().has_header("Content-Encoding"));
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();

    auto req = create_request(qb::http::method::POST, "/test_no_decompress", compressed_body, "gzip");
    make_request(std::move(req));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(CompressionMiddlewareTest, ResponseCompressionAppliedEvenIfNotSmallerWhenConditionsMet) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(1); // Compress even tiny bodies
    auto comp_mw = qb::http::compression_middleware<MockCompressionSession>(opts);

    std::string original_body_content = "abc";
    _router = std::make_unique<qb::http::Router<MockCompressionSession> >();
    _router->use(comp_mw);
    _router->get("/test_non_compressible_but_applied", success_handler(original_body_content));
    _router->compile();

    auto req = create_request(qb::http::method::GET, "/test_non_compressible_but_applied");
    req.set_header("Accept-Encoding", "gzip");
    make_request(std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);

    // With the current middleware logic, Content-Encoding WILL be set.
    EXPECT_TRUE(_session->_response.has_header("Content-Encoding"))
        << "Content-Encoding should be set if compress() > 0 and other conditions met.";
    EXPECT_EQ(_session->_response.header("Content-Encoding"), "gzip");

    // The body will be the compressed version. We need to compress the original to compare.
    qb::http::Body expected_compressed_body_obj;
    expected_compressed_body_obj = original_body_content;
    size_t expected_compressed_size = expected_compressed_body_obj.compress("gzip");

    EXPECT_EQ(_session->_response.body().as<std::string>(), expected_compressed_body_obj.as<std::string>());

    if (_session->_response.has_header("Content-Length")) {
        EXPECT_EQ(_session->_response.header("Content-Length"), std::to_string(expected_compressed_size));
    }
}

TEST_F(CompressionMiddlewareTest, ResponseCompressionSelectsCorrectEncodingBasedOnServerAndClientPreferences) {
    std::string original_response_body =
            "This is a response body for encoding selection testing, long enough for compression.";

    // Case 1: Server prefers gzip, client sends deflate, gzip
    qb::http::CompressionOptions opts_server_prefers_gzip;
    opts_server_prefers_gzip.compress_responses(true)
            .min_size_to_compress(10)
            .preferred_encodings({"gzip", "deflate"});
    auto mw_server_prefers_gzip = qb::http::compression_middleware<MockCompressionSession>(opts_server_prefers_gzip);

    _router = std::make_unique<qb::http::Router<MockCompressionSession> >();
    _router->use(mw_server_prefers_gzip);
    _router->get("/test_encoding_pref1", success_handler(original_response_body));
    _router->compile();

    auto req1 = create_request(qb::http::method::GET, "/test_encoding_pref1");
    req1.set_header("Accept-Encoding", "deflate, gzip");
    make_request(std::move(req1));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.header("Content-Encoding"), "gzip");
    qb::http::Body temp_body_decompress1;
    temp_body_decompress1 = _session->_response.body().as<std::string>();
    temp_body_decompress1.uncompress("gzip");
    EXPECT_EQ(temp_body_decompress1.as<std::string>(), original_response_body);

    _session->reset(); // Reset session for the next case

    // Case 2: Server prefers deflate, client sends deflate, gzip
    qb::http::CompressionOptions opts_server_prefers_deflate;
    opts_server_prefers_deflate.compress_responses(true)
            .min_size_to_compress(10)
            .preferred_encodings({"deflate", "gzip"});
    auto mw_server_prefers_deflate = qb::http::compression_middleware<MockCompressionSession>(
        opts_server_prefers_deflate);

    _router = std::make_unique<qb::http::Router<MockCompressionSession> >();
    _router->use(mw_server_prefers_deflate);
    _router->get("/test_encoding_pref2", success_handler(original_response_body));
    _router->compile();

    auto req2 = create_request(qb::http::method::GET, "/test_encoding_pref2");
    req2.set_header("Accept-Encoding", "deflate, gzip"); // Client accepts both
    make_request(std::move(req2));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.header("Content-Encoding"), "deflate");
    qb::http::Body temp_body_decompress2;
    temp_body_decompress2 = _session->_response.body().as<std::string>();
    temp_body_decompress2.uncompress("deflate");
    EXPECT_EQ(temp_body_decompress2.as<std::string>(), original_response_body);
}

TEST_F(CompressionMiddlewareTest, ResponseCompressionUsesFirstServerPreferenceIfClientAcceptsWildcard) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true)
            .min_size_to_compress(10)
            .preferred_encodings({"deflate", "gzip"}); // Server prefers deflate first
    auto comp_mw = qb::http::compression_middleware<MockCompressionSession>(opts);

    std::string original_response_body = "This is a response body for wildcard accept-encoding testing.";
    _router = std::make_unique<qb::http::Router<MockCompressionSession> >();
    _router->use(comp_mw);
    _router->get("/test_wildcard_accept", success_handler(original_response_body));
    _router->compile();

    auto req = create_request(qb::http::method::GET, "/test_wildcard_accept");
    req.set_header("Accept-Encoding", "*"); // Client accepts any
    make_request(std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.header("Content-Encoding"), "deflate"); // Should pick server's first preference

    qb::http::Body temp_body_decompress;
    temp_body_decompress = _session->_response.body().as<std::string>();
    temp_body_decompress.uncompress("deflate");
    EXPECT_EQ(temp_body_decompress.as<std::string>(), original_response_body);
}

TEST_F(CompressionMiddlewareTest, ResponseCompressionNotAppliedIfNoCommonSupportedEncoding) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true)
            .min_size_to_compress(10)
            .preferred_encodings({"gzip", "deflate"}); // Server supports gzip and deflate
    auto comp_mw = qb::http::compression_middleware<MockCompressionSession>(opts);

    std::string original_response_body = "This response body will not be compressed due to no common encoding.";
    _router = std::make_unique<qb::http::Router<MockCompressionSession> >();
    _router->use(comp_mw);
    _router->get("/test_no_common_encoding", success_handler(original_response_body));
    _router->compile();

    auto req = create_request(qb::http::method::GET, "/test_no_common_encoding");
    // Client only accepts 'br' (Brotli), which server isn't configured to offer here
    req.set_header("Accept-Encoding", "br");
    make_request(std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_FALSE(_session->_response.has_header("Content-Encoding"));
    EXPECT_EQ(_session->_response.body().as<std::string>(), original_response_body);
}

#endif // QB_IO_WITH_ZLIB

TEST_F(CompressionMiddlewareTest, FactoryFunctions) {
    auto default_mw = qb::http::compression_middleware<MockCompressionSession>();
    EXPECT_EQ(default_mw->name(), "CompressionMiddleware");
    EXPECT_TRUE(default_mw->get_options().should_compress_responses());

    auto max_mw = qb::http::max_compression_middleware<MockCompressionSession>();
    EXPECT_EQ(max_mw->name(), "MaxCompressionMiddleware");
    EXPECT_EQ(max_mw->get_options().get_min_size_to_compress(), 256);

    auto fast_mw = qb::http::fast_compression_middleware<MockCompressionSession>();
    EXPECT_EQ(fast_mw->name(), "FastCompressionMiddleware");
    EXPECT_EQ(fast_mw->get_options().get_min_size_to_compress(), 2048);
}

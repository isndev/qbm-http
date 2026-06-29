/**
 * @file qbm/http/tests/unit/middleware/middleware-compression.cpp
 * @brief Unit tests for qb::http::CompressionMiddleware.
 *
 * Drives the real qb::http::Router<Session> synchronously over the shared
 * capturing MockMiddlewareSession (no qb::Main, no socket): a request is routed
 * and the finalized Response is asserted. Two halves:
 *
 *   - Always-on: factory names + option defaults (the `*_middleware` factories
 *     and CompressionOptions are pure, no zlib link).
 *   - `#ifdef QB_HAS_COMPRESSION`: the real codec round-trips. Request bodies
 *     are decompressed before the handler (and Content-Encoding stripped /
 *     Content-Length updated); response bodies are compressed in a
 *     PRE_RESPONSE_SEND lifecycle hook with full Accept-Encoding q-value
 *     negotiation. Every "compressed" assertion decompresses the wire body and
 *     compares against the original (no header-only verification).
 *
 * The qb-io codec ships gzip + deflate only (no brotli): `br` is therefore the
 * canonical "client wants an encoding the server cannot offer" negative path.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "../../shared/middleware_test_fixture.h"

#include "../middleware/compression.h"
#include "../routing/middleware.h"

using qb::http::test::MockMiddlewareSession;

namespace {

class CompressionMiddlewareTest : public qb::http::test::MiddlewareTestFixture<MockMiddlewareSession> {
protected:
    qb::http::Request
    body_request(qb::http::method method_val, const std::string &target_path, const std::string &body_content = "",
                 const std::string &content_encoding = "") {
        qb::http::Request req = create_request(method_val, target_path);
        if (!body_content.empty()) {
            req.body() = body_content;
            req.set_header("Content-Length", std::to_string(body_content.length()));
        }
        if (!content_encoding.empty()) {
            req.set_header("Content-Encoding", content_encoding);
        }
        return req;
    }

    qb::http::RouteHandlerFn<MockMiddlewareSession>
    body_emitting_handler(const std::string &response_body, const std::string &content_type = "text/plain") {
        return [this, response_body, content_type](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
            _session->_final_handler_called = true;
            ctx->response().status()        = qb::http::status::OK;
            ctx->response().set_header("Content-Type", content_type);
            ctx->response().body() = response_body;
            ctx->complete();
        };
    }

    /** @brief Mounts @p mw ahead of a GET handler at @p path emitting @p body, then routes @p req. */
    void
    run_get(std::shared_ptr<qb::http::IMiddleware<MockMiddlewareSession>> mw, const std::string &path, const std::string &body,
            qb::http::Request req, const std::string &content_type = "text/plain") {
        _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
        _router->use(std::move(mw));
        _router->get(path, body_emitting_handler(body, content_type));
        _router->compile();
        _session->reset();
        _router->route(_session, std::move(req));
    }
};

#ifdef QB_HAS_COMPRESSION

// --- Request decompression -------------------------------------------------

TEST_F(CompressionMiddlewareTest, DecompressesGzipRequestAndUpdatesFraming) {
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>();

    const std::string original_body = "This is test data for gzip.";
    qb::http::Body    gz;
    gz = original_body;
    gz.compress("gzip");
    const std::string compressed_body = gz.as<std::string>();
    ASSERT_NE(original_body, compressed_body);

    _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
    _router->use(comp_mw);
    _router->post("/test", [this, original_body](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
        _session->_final_handler_called = true;
        // Handler sees the DECODED body, no Content-Encoding, and a Content-Length
        // updated to the decompressed length (chunked/encoded framing rewritten).
        EXPECT_EQ(ctx->request().body().as<std::string>(), original_body);
        EXPECT_FALSE(ctx->request().has_header("Content-Encoding"));
        ASSERT_TRUE(ctx->request().has_header("Content-Length"));
        EXPECT_EQ(ctx->request().header("Content-Length"), std::to_string(original_body.length()));
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();

    _session->reset();
    _router->route(_session, body_request(qb::http::method::POST, "/test", compressed_body, "gzip"));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(CompressionMiddlewareTest, DecompressesDeflateRequest) {
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>();

    const std::string original_body(512, 'Z'); // highly compressible
    qb::http::Body    df;
    df = original_body;
    df.compress("deflate");
    const std::string compressed_body = df.as<std::string>();
    ASSERT_NE(original_body, compressed_body);

    _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
    _router->use(comp_mw);
    _router->post("/test", [this, original_body](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
        _session->_final_handler_called = true;
        EXPECT_EQ(ctx->request().body().as<std::string>(), original_body);
        EXPECT_FALSE(ctx->request().has_header("Content-Encoding"));
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();

    _session->reset();
    _router->route(_session, body_request(qb::http::method::POST, "/test", compressed_body, "deflate"));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(CompressionMiddlewareTest, HandlesInvalidCompressedData) {
    qb::http::CompressionOptions opts;
    opts.decompress_requests(true);
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
    _router->use(comp_mw);
    _router->post("/test", body_emitting_handler("unreached"));
    _router->compile();

    _session->reset();
    _router->route(_session, body_request(qb::http::method::POST, "/test", "not_actually_gzipped_data", "gzip"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_NE(_session->_response.body().as<std::string>().find("Invalid compressed request body"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(CompressionMiddlewareTest, SkipsDecompressionWhenOptionDisabled) {
    qb::http::CompressionOptions opts;
    opts.decompress_requests(false);
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    qb::http::Body gz;
    gz = std::string("This is test data for gzip.");
    gz.compress("gzip");
    const std::string compressed_body = gz.as<std::string>();

    _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
    _router->use(comp_mw);
    _router->post("/test", [this, compressed_body](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
        _session->_final_handler_called = true;
        EXPECT_EQ(ctx->request().body().as<std::string>(), compressed_body); // still compressed
        EXPECT_TRUE(ctx->request().has_header("Content-Encoding"));
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();

    _session->reset();
    _router->route(_session, body_request(qb::http::method::POST, "/test", compressed_body, "gzip"));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

// --- Response compression --------------------------------------------------

TEST_F(CompressionMiddlewareTest, CompressesResponseGzip) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(10);
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    const std::string original(2048, 'A');
    auto              req = create_request(qb::http::method::GET, "/test");
    req.set_header("Accept-Encoding", "gzip, deflate");
    run_get(comp_mw, "/test", original, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.header("Content-Encoding"), "gzip");
    EXPECT_EQ(_session->_response.header("Vary"), "Accept-Encoding");
    // Content-Length must match the COMPRESSED wire size (framing updated).
    EXPECT_EQ(_session->_response.header("Content-Length"), std::to_string(_session->_response.body().size()));
    EXPECT_LT(_session->_response.body().size(), original.size());

    qb::http::Body dec;
    dec = _session->_response.body().as<std::string>();
    dec.uncompress("gzip");
    EXPECT_EQ(dec.as<std::string>(), original);
}

TEST_F(CompressionMiddlewareTest, ResponseHookSurvivesMiddlewareDestruction) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(10);
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    auto req = create_request(qb::http::method::GET, "/test");
    req.set_header("Accept-Encoding", "gzip");
    auto ctx = std::make_shared<qb::http::Context<MockMiddlewareSession>>(
        std::move(req), qb::http::Response{}, _session, [](qb::http::Context<MockMiddlewareSession> &) {},
        std::weak_ptr<qb::http::RouterCore<MockMiddlewareSession>>{});
    const std::string original(2048, 'D');
    ctx->response().set_header("Content-Type", "text/plain");
    ctx->response().body() = original;

    comp_mw->process(ctx);
    comp_mw.reset(); // hook captured an options snapshot — must survive this.

    ctx->execute_hook(qb::http::HookPoint::PRE_RESPONSE_SEND);

    EXPECT_EQ(ctx->response().header("Content-Encoding"), "gzip");
    qb::http::Body dec;
    dec = ctx->response().body().as<std::string>();
    dec.uncompress("gzip");
    EXPECT_EQ(dec.as<std::string>(), original);
}

TEST_F(CompressionMiddlewareTest, DoesNotCompressSmallResponses) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(1000);
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    const std::string small = "Small body.";
    auto              req   = create_request(qb::http::method::GET, "/small");
    req.set_header("Accept-Encoding", "gzip");
    run_get(comp_mw, "/small", small, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_FALSE(_session->_response.has_header("Content-Encoding"));
    EXPECT_EQ(_session->_response.body().as<std::string>(), small);
}

TEST_F(CompressionMiddlewareTest, SkipsAlreadyCompressedContentTypes) {
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>();

    const std::string jpeg = "some_jpeg_data_long_enough_to_compress";
    auto              req  = create_request(qb::http::method::GET, "/image.jpg");
    req.set_header("Accept-Encoding", "gzip");
    run_get(comp_mw, "/image.jpg", jpeg, std::move(req), "image/jpeg");

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_FALSE(_session->_response.has_header("Content-Encoding"));
    EXPECT_EQ(_session->_response.body().as<std::string>(), jpeg);
}

TEST_F(CompressionMiddlewareTest, SkipsCompressionWhenOptionDisabled) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(false);
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    auto req = create_request(qb::http::method::GET, "/no_compress");
    req.set_header("Accept-Encoding", "gzip");
    run_get(comp_mw, "/no_compress", "This normally would compress.", std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_FALSE(_session->_response.has_header("Content-Encoding"));
}

TEST_F(CompressionMiddlewareTest, KeepsOriginalBodyWhenCompressionExpandsPayload) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(1); // try to compress even "abc"
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    const std::string original = "abc";
    auto              req      = create_request(qb::http::method::GET, "/tiny");
    req.set_header("Accept-Encoding", "gzip");
    run_get(comp_mw, "/tiny", original, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_FALSE(_session->_response.has_header("Content-Encoding")); // gzip framing would grow it
    EXPECT_EQ(_session->_response.body().as<std::string>(), original);
}

// --- Encoding selection / q-values -----------------------------------------

TEST_F(CompressionMiddlewareTest, ServerPreferenceBreaksTieGzipFirst) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(10).preferred_encodings({"gzip", "deflate"});
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    const std::string original(4096, 'B');
    auto              req = create_request(qb::http::method::GET, "/pref");
    req.set_header("Accept-Encoding", "deflate, gzip"); // both q=1; server tie-break -> gzip
    run_get(comp_mw, "/pref", original, std::move(req));

    EXPECT_EQ(_session->_response.header("Content-Encoding"), "gzip");
    qb::http::Body dec;
    dec = _session->_response.body().as<std::string>();
    dec.uncompress("gzip");
    EXPECT_EQ(dec.as<std::string>(), original);
}

TEST_F(CompressionMiddlewareTest, ServerPreferenceBreaksTieDeflateFirst) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(10).preferred_encodings({"deflate", "gzip"});
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    const std::string original(4096, 'B');
    auto              req = create_request(qb::http::method::GET, "/pref2");
    req.set_header("Accept-Encoding", "deflate, gzip");
    run_get(comp_mw, "/pref2", original, std::move(req));

    EXPECT_EQ(_session->_response.header("Content-Encoding"), "deflate");
    qb::http::Body dec;
    dec = _session->_response.body().as<std::string>();
    dec.uncompress("deflate");
    EXPECT_EQ(dec.as<std::string>(), original);
}

TEST_F(CompressionMiddlewareTest, WildcardAcceptUsesFirstServerPreference) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(10).preferred_encodings({"deflate", "gzip"});
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    const std::string original(4096, 'C');
    auto              req = create_request(qb::http::method::GET, "/wild");
    req.set_header("Accept-Encoding", "*");
    run_get(comp_mw, "/wild", original, std::move(req));

    EXPECT_EQ(_session->_response.header("Content-Encoding"), "deflate");
    qb::http::Body dec;
    dec = _session->_response.body().as<std::string>();
    dec.uncompress("deflate");
    EXPECT_EQ(dec.as<std::string>(), original);
}

TEST_F(CompressionMiddlewareTest, NotAppliedIfNoCommonEncoding_BrotliNotSupported) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(10).preferred_encodings({"gzip", "deflate"});
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    // qb-io ships gzip+deflate only; the client asking exclusively for brotli
    // leaves no common encoding -> body served uncompressed, no Content-Encoding.
    const std::string original = "This response body will not be compressed; only br requested.";
    auto              req      = create_request(qb::http::method::GET, "/br");
    req.set_header("Accept-Encoding", "br");
    run_get(comp_mw, "/br", original, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_FALSE(_session->_response.has_header("Content-Encoding"));
    EXPECT_EQ(_session->_response.body().as<std::string>(), original);
}

TEST_F(CompressionMiddlewareTest, HonorsQValuesGzipZeroPicksDeflate) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(10).preferred_encodings({"gzip", "deflate"});
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    const std::string original(4096, 'E');
    auto              req = create_request(qb::http::method::GET, "/q");
    req.set_header("Accept-Encoding", "gzip;q=0, deflate;q=1"); // gzip explicitly refused
    run_get(comp_mw, "/q", original, std::move(req));

    EXPECT_EQ(_session->_response.header("Content-Encoding"), "deflate");
    qb::http::Body dec;
    dec = _session->_response.body().as<std::string>();
    dec.uncompress("deflate");
    EXPECT_EQ(dec.as<std::string>(), original);
}

TEST_F(CompressionMiddlewareTest, ZeroQRejectsEncodingEvenThroughWildcard) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(10).preferred_encodings({"gzip"});
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    const std::string original(4096, 'F');
    auto              req = create_request(qb::http::method::GET, "/qz");
    req.set_header("Accept-Encoding", "gzip;q=0, *;q=1"); // explicit gzip=0 overrides the wildcard
    run_get(comp_mw, "/qz", original, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_FALSE(_session->_response.has_header("Content-Encoding"));
    EXPECT_EQ(_session->_response.body().as<std::string>(), original);
}

TEST_F(CompressionMiddlewareTest, RejectsMalformedQValue) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(10).preferred_encodings({"gzip"});
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    const std::string original(4096, 'G');
    auto              req = create_request(qb::http::method::GET, "/badq");
    req.set_header("Accept-Encoding", "gzip;q=0.5junk"); // malformed q -> treated as q=0
    run_get(comp_mw, "/badq", original, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_FALSE(_session->_response.has_header("Content-Encoding"));
    EXPECT_EQ(_session->_response.body().as<std::string>(), original);
}

#endif // QB_HAS_COMPRESSION

// --- Always-on (no zlib link required) -------------------------------------

TEST_F(CompressionMiddlewareTest, FactoryFunctions) {
    auto default_mw = qb::http::compression_middleware<MockMiddlewareSession>();
    EXPECT_EQ(default_mw->name(), "CompressionMiddleware");
    EXPECT_TRUE(default_mw->get_options().should_compress_responses());
    EXPECT_TRUE(default_mw->get_options().should_decompress_requests());

    auto max_mw = qb::http::max_compression_middleware<MockMiddlewareSession>();
    EXPECT_EQ(max_mw->name(), "MaxCompressionMiddleware");
    EXPECT_EQ(max_mw->get_options().get_min_size_to_compress(), 256u);

    auto fast_mw = qb::http::fast_compression_middleware<MockMiddlewareSession>();
    EXPECT_EQ(fast_mw->name(), "FastCompressionMiddleware");
    EXPECT_EQ(fast_mw->get_options().get_min_size_to_compress(), 2048u);
}

TEST_F(CompressionMiddlewareTest, OptionsDefaultsAndPreferenceOrder) {
    qb::http::CompressionOptions opts;
    EXPECT_TRUE(opts.should_compress_responses());
    EXPECT_TRUE(opts.should_decompress_requests());
    EXPECT_EQ(opts.get_min_size_to_compress(), 1024u);
    // Default server preference list is gzip-first, deflate-second.
    ASSERT_EQ(opts.get_preferred_encodings().size(), 2u);
    EXPECT_EQ(opts.get_preferred_encodings()[0], "gzip");
    EXPECT_EQ(opts.get_preferred_encodings()[1], "deflate");
}

} // namespace

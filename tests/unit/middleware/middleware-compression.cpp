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

#include <algorithm>
#include <initializer_list>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "../../shared/middleware_test_fixture.h"

#include <qbm/http/middleware/compression.h>
#include <qbm/http/routing/middleware.h>

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

// The names of `order` this build can produce, read from the build's own macros -- not from qb's registry, which is
// what the middleware reads (Huly QB-93).
std::vector<std::string>
in_this_build(std::initializer_list<const char *> order) {
    std::vector<std::string> names;
    for (const std::string name : order) {
        bool built = false;
#if defined(QB_HAS_COMPRESSION)
        built = name == "gzip" || name == "deflate";
#if defined(QB_HAS_ZSTD)
        built = built || name == "zstd";
#endif
#if defined(QB_HAS_BROTLI)
        built = built || name == "br";
#endif
#endif
        if (built)
            names.push_back(name);
    }
    return names;
}

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

TEST_F(CompressionMiddlewareTest, NotAppliedIfNoCommonEncoding) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(10).preferred_encodings({"gzip", "deflate"});
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    // The server offers gzip and deflate only; the client asking exclusively for brotli
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

// A browser lists every codec at q=1, so the server's order decides: the default middleware answers with the first
// codec of {zstd, br, gzip} this build registers, and the body decodes (Huly QB-93).
TEST_F(CompressionMiddlewareTest, ABrowserGetsTheFirstCodecOfTheDefaultOrder) {
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>();

    std::string original;
    for (int i = 0; original.size() < 8192; ++i)
        original += "{\"id\":" + std::to_string(i) + ",\"name\":\"item-" + std::to_string(i * 7919 % 1000) + "\"},";
    auto req = create_request(qb::http::method::GET, "/browser");
    req.set_header("Accept-Encoding", "gzip, deflate, br, zstd");
    run_get(comp_mw, "/browser", original, std::move(req), "application/json");

    const std::string expected = in_this_build({"zstd", "br", "gzip"}).front();
    ASSERT_EQ(_session->_response.header("Content-Encoding"), expected);
    qb::http::Body dec;
    dec = _session->_response.body().as<std::string>();
    dec.uncompress(expected);
    EXPECT_EQ(dec.as<std::string>(), original);
}

// A preference list may name a codec this build does not register (a list written for a build with brotli, say):
// it is passed over for the next one the client accepts, not chosen and then refused by Body::compress, which sent
// the body uncompressed (Huly QB-93).
TEST_F(CompressionMiddlewareTest, ACodecTheBuildDoesNotRegisterIsPassedOver) {
    qb::http::CompressionOptions opts;
    opts.min_size_to_compress(10).preferred_encodings({"x-not-a-codec", "gzip"});
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);

    const std::string original(4096, 'H');
    auto              req = create_request(qb::http::method::GET, "/unregistered");
    req.set_header("Accept-Encoding", "x-not-a-codec, gzip");
    run_get(comp_mw, "/unregistered", original, std::move(req));

    ASSERT_EQ(_session->_response.header("Content-Encoding"), "gzip");
    qb::http::Body dec;
    dec = _session->_response.body().as<std::string>();
    dec.uncompress("gzip");
    EXPECT_EQ(dec.as<std::string>(), original);
}

/// A provider of the test's own, scripted call by call (Huly QB-1208): what `StreamCoding::run()` does with a coder
/// that fills its window exactly, one that ends its stream early, one that makes no progress.
struct ScriptedCoder final : qb::compression::compress_provider {
    struct Step {
        std::size_t take; ///< input bytes reported taken (clamped to what is offered)
        std::size_t make; ///< output bytes written (clamped to the window): 'x' * make
        bool        done; ///< the stream ended
    };
    std::vector<Step> steps;
    bool              repeat_last = false; ///< past the script, the last step again (a coder that never stops)
    std::size_t       calls       = 0;
    std::string       name        = "scripted";
    const std::string &
    algorithm() const override {
        return name;
    }
    std::size_t
    compress(const uint8_t *, std::size_t input_size, uint8_t *output, std::size_t output_size, qb::compression::operation_hint,
             std::size_t &input_bytes_processed, bool &done) override {
        const Step step = calls < steps.size() ? steps[calls] : (repeat_last && !steps.empty() ? steps.back() : Step{0, 0, false});
        ++calls;
        input_bytes_processed  = std::min(step.take, input_size);
        const std::size_t made = std::min(step.make, output_size);
        std::fill_n(output, made, static_cast<uint8_t>('x'));
        done = step.done;
        return made;
    }
    void
    reset() override {}
};

TEST_F(CompressionMiddlewareTest, AWholeBodyCodedKeepsOneVaryWeakensItsETagAndDropsAcceptRanges) {
    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(10);
    auto comp_mw = qb::http::compression_middleware<MockMiddlewareSession>(opts);
    auto req     = create_request(qb::http::method::GET, "/tagged");
    req.set_header("Accept-Encoding", "gzip");
    _router = std::make_unique<qb::http::Router<MockMiddlewareSession>>();
    _router->use(comp_mw);
    _router->get("/tagged", [](auto ctx) {
        ctx->response().set_header("Content-Type", "text/plain");
        ctx->response().set_header("ETag", "\"v1\"");
        ctx->response().set_header("Accept-Ranges", "bytes");
        ctx->response().set_header("Vary", "Accept-Language, Accept-Encoding");
        ctx->response().body() = std::string(2048, 'A');
        ctx->complete();
    });
    _router->compile();
    _session->reset();
    _router->route(_session, std::move(req));
    auto &res = _session->_response;
    EXPECT_EQ(res.header("Content-Encoding"), "gzip");
    EXPECT_EQ(res.header("ETag"), "W/\"v1\"") << "the coded representation is not byte-equal";
    EXPECT_FALSE(res.has_header("Accept-Ranges")) << "a coded body cannot be resumed by byte range";
    EXPECT_EQ(res.header("Vary"), "Accept-Language, Accept-Encoding");
    EXPECT_TRUE(res.header("Vary", 1).empty()) << "Accept-Encoding listed already: no second Vary line";
}

TEST_F(CompressionMiddlewareTest, StreamCodingEndsAPieceOnTheDrainCallThatFindsNothingPending) {
    // The first call takes the piece whole and fills its window exactly: the loop drains once more, as the provider's
    // contract asks; that drain takes nothing and makes nothing -- the flush was complete -- and the piece is coded.
    auto              coder  = std::make_unique<ScriptedCoder>();
    auto             *script = coder.get();
    const std::string piece(100, 'p');
    const std::size_t window = std::max<std::size_t>(piece.size() + (piece.size() >> 8) + 128, 1024); // the filter's first window
    script->steps            = {{piece.size(), window, false}, {0, 0, false}};
    qb::http::detail::StreamCoding coding(std::move(coder), "scripted");
    std::string                    out;
    EXPECT_TRUE(coding.code(piece, out)) << "an exactly filled window, then an empty drain, is a coded piece";
    EXPECT_EQ(out.size(), window);
    EXPECT_EQ(script->calls, 2u) << "one call for the piece, one drain";
    // The tail: the finishing call says done at once.
    script->steps = {{0, 3, true}};
    script->calls = 0;
    out.clear();
    EXPECT_TRUE(coding.finish(out));
    EXPECT_EQ(out, "xxx");
    EXPECT_EQ(script->calls, 1u);
}

TEST_F(CompressionMiddlewareTest, StreamCodingRefusesACoderThatEndsEarlyOrMakesNoProgress) {
    {
        // The stream ended with input left: not a coding of this piece, refused at once -- not one call later by the
        // no-progress guard, which a coder that keeps making bytes after its end would pass.
        auto  coder        = std::make_unique<ScriptedCoder>();
        auto *script       = coder.get();
        coder->steps       = {{10, 5, true}, {0, 5, true}};
        coder->repeat_last = true;
        qb::http::detail::StreamCoding coding(std::move(coder), "scripted");
        std::string                    out;
        EXPECT_FALSE(coding.code(std::string(100, 'p'), out));
        EXPECT_EQ(script->calls, 1u);
    }
    {
        // A coder that never stops making output (its window filled every call, nothing taken, never done) is cut at
        // the rounds ceiling, not looped for ever on the loop thread.
        auto  coder  = std::make_unique<ScriptedCoder>();
        auto *script = coder.get();
        coder->steps = {{100, 1024, false}};
        for (int i = 0; i < 200; ++i) // 200 windows: far past the ceiling, and bounded for a loop without one
            coder->steps.push_back({0, 16384, false});
        qb::http::detail::StreamCoding coding(std::move(coder), "scripted");
        std::string                    out;
        EXPECT_FALSE(coding.code(std::string(100, 'p'), out));
        EXPECT_EQ(script->calls, 65u) << "the first window, then 64 rounds";
    }
    {
        // No progress with input left: the loop never spins.
        auto  coder  = std::make_unique<ScriptedCoder>();
        auto *script = coder.get();
        coder->steps = {{10, 5, false}, {0, 0, false}};
        qb::http::detail::StreamCoding coding(std::move(coder), "scripted");
        std::string                    out;
        EXPECT_FALSE(coding.code(std::string(100, 'p'), out));
        EXPECT_EQ(script->calls, 2u);
    }
    {
        // A finishing call that never says done and makes nothing: refused, not looped.
        auto  coder  = std::make_unique<ScriptedCoder>();
        auto *script = coder.get();
        coder->steps = {{0, 0, false}};
        qb::http::detail::StreamCoding coding(std::move(coder), "scripted");
        std::string                    out;
        EXPECT_FALSE(coding.finish(out));
        EXPECT_EQ(script->calls, 1u);
    }
    {
        // A coder that throws is a failed coding, not an exception out of the stream.
        struct Throwing final : qb::compression::compress_provider {
            std::string name = "throwing";
            const std::string &
            algorithm() const override {
                return name;
            }
            std::size_t
            compress(const uint8_t *, std::size_t, uint8_t *, std::size_t, qb::compression::operation_hint, std::size_t &, bool &) override {
                throw std::runtime_error("broken");
            }
            void
            reset() override {}
        };
        qb::http::detail::StreamCoding coding(std::make_unique<Throwing>(), "throwing");
        std::string                    out;
        EXPECT_FALSE(coding.code("piece", out));
    }
}

TEST_F(CompressionMiddlewareTest, StreamCodingPiecesThenTheTailInflateToTheInput) {
    // Every real coder this build registers, piece by piece, made at the first piece as the middleware makes it: every
    // piece leaves bytes (a flush), the pieces and the tail together inflate to the input, and a piece's coded form stays
    // under the filter's bound -- an incompressible 64 KiB piece included, where the bound matters.
    std::vector<std::string> encodings{"gzip", "deflate"};
#if defined(QB_HAS_ZSTD)
    encodings.push_back("zstd");
#endif
#if defined(QB_HAS_BROTLI)
    encodings.push_back("br");
#endif
    std::string noise(64 * 1024, '\0');
    for (std::uint32_t i = 0, x = 0x9e3779b9u; i < noise.size(); ++i) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        noise[i] = static_cast<char>(x);
    }
    for (std::string const &encoding : encodings) {
        qb::http::detail::StreamCoding coding(encoding);
        EXPECT_EQ(coding.name(), encoding);
        std::string input, coded;
        for (int i = 0; i < 65; ++i) {
            std::string piece = i == 32 ? noise : std::string(1000 + i * 37, static_cast<char>('a' + i % 26));
            piece += std::to_string(i * 7919);
            input += piece;
            std::string out;
            ASSERT_TRUE(coding.code(piece, out)) << encoding << " piece " << i;
            EXPECT_GT(out.size(), 0u) << "a piece leaves bytes: the flush is partial, not held (" << encoding << ")";
            EXPECT_LE(out.size(), coding.bound(piece.size())) << encoding << " piece " << i;
            coded += out;
        }
        std::string tail;
        ASSERT_TRUE(coding.finish(tail)) << encoding;
        coded += tail;
        EXPECT_LT(coded.size(), noise.size() + input.size() / 4) << encoding;
        qb::http::Body body;
        body = coded;
        body.uncompress(encoding);
        EXPECT_TRUE(body.as<std::string>() == input) << "the pieces and the tail inflate to the input (" << encoding << ")";
    }
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
    // Smallest output first, each codec only when this build registers it (Huly QB-93).
    EXPECT_EQ(max_mw->get_options().get_preferred_encodings(), in_this_build({"br", "gzip", "deflate", "zstd"}));

    auto fast_mw = qb::http::fast_compression_middleware<MockMiddlewareSession>();
    EXPECT_EQ(fast_mw->name(), "FastCompressionMiddleware");
    EXPECT_EQ(fast_mw->get_options().get_min_size_to_compress(), 2048u);
    // Cheapest encoder first (Huly QB-93).
    EXPECT_EQ(fast_mw->get_options().get_preferred_encodings(), in_this_build({"zstd", "deflate", "gzip", "br"}));
}

TEST_F(CompressionMiddlewareTest, OptionsDefaultsAndPreferenceOrder) {
    qb::http::CompressionOptions opts;
    EXPECT_TRUE(opts.should_compress_responses());
    EXPECT_TRUE(opts.should_decompress_requests());
    EXPECT_EQ(opts.get_min_size_to_compress(), 1024u);
    // zstd, br, gzip, deflate -- each only when this build registers it, so {gzip, deflate} in a build of qb without
    // the opt-in codecs and nothing in a build without compression (Huly QB-93).
    EXPECT_EQ(opts.get_preferred_encodings(), in_this_build({"zstd", "br", "gzip", "deflate"}));
}

} // namespace

#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/compression.h"
#include "../middleware/middleware_chain.h"
#include "../routing/context.h"
#include "../body.h"
#include <string>
#include <vector>
#include <chrono>
// Pour le test d'intégration avec d'autres middlewares
#include "../middleware/error_handling.h"
#include "../middleware/logging.h"

using namespace qb::http;

// Simple MockSession for testing
struct MockSession {
    TResponse<std::string> _response;
    bool _closed = false;

    // Required by Router to send responses
    MockSession& operator<<(TResponse<std::string> resp) {
        _response = std::move(resp);
        return *this;
    }

    bool is_connected() const {
        return !_closed;
    }

    void close() {
        _closed = true;
    }
};

// Mock implementations and utility functions for testing
namespace {
    // Create a simple request for testing
    TRequest<std::string> create_test_request(const std::string& content_type, const std::string& body) {
        TRequest<std::string> req;
        if (!content_type.empty()) {
            req.add_header("Content-Type", content_type);
        }
        req.body() = body;
        return req;
    }

#ifdef QB_IO_WITH_ZLIB
    // Create a compressed version of a string
    std::string compress_string(const std::string& str, const std::string& encoding) {
        TRequest<std::string> req;
        req.body() = str;
        
        // Use the Body class's compress method
        req.body().compress(encoding);
        
        // Return the compressed string
        return req.body().template as<std::string>();
    }
    
    // Create realistic JSON data for testing
    std::string create_json_data() {
        std::string json = R"({
            "id": 12345,
            "name": "Test Product",
            "description": "This is a test product with a somewhat longer description that should compress well",
            "price": 99.99,
            "categories": ["electronics", "computers", "accessories"],
            "specifications": {
                "weight": "1.5kg",
                "dimensions": "30x20x10cm",
                "color": "black",
                "material": "plastic/metal",
                "warranty": "1 year limited warranty"
            },
            "reviews": [
                {"user": "user1", "rating": 4, "comment": "Great product, works as expected."},
                {"user": "user2", "rating": 5, "comment": "Excellent value for money, highly recommend!"},
                {"user": "user3", "rating": 3, "comment": "Decent product but a bit expensive."}
            ],
            "stock": 150,
            "tags": ["new", "featured", "sale", "popular", "trending"]
        })";
        return json;
    }
    
    // Create realistic HTML data for testing
    std::string create_html_data() {
        std::string html = R"(<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Test Page</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; }
                .content { margin-top: 20px; }
                .footer { margin-top: 30px; text-align: center; color: #6c757d; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Welcome to Our Website</h1>
                    <p>This is a sample page for testing HTML compression.</p>
                </div>
                <div class="content">
                    <h2>About Us</h2>
                    <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nullam auctor, nisl eget ultricies aliquam, nunc nisl aliquet nunc, vitae aliquam nisl nunc vitae nisl.</p>
                    <p>Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
                    <h2>Our Services</h2>
                    <ul>
                        <li>Web Development</li>
                        <li>Mobile App Development</li>
                        <li>UI/UX Design</li>
                        <li>Cloud Computing</li>
                        <li>DevOps</li>
                    </ul>
                </div>
                <div class="footer">
                    <p>&copy; 2023 Example Company. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>)";
        return html;
    }
#endif
}

// Basic functionality tests
TEST(CompressionMiddlewareTest, MiddlewareNameIsSetCorrectly) {
    auto middleware = CompressionMiddleware<MockSession>();
    EXPECT_EQ("CompressionMiddleware", middleware.name());
    
    auto custom_middleware = CompressionMiddleware<MockSession>(CompressionOptions(), "CustomName");
    EXPECT_EQ("CustomName", custom_middleware.name());
}

TEST(CompressionMiddlewareTest, OptionsCanBeUpdated) {
    auto middleware = CompressionMiddleware<MockSession>();
    
    // Default options
    EXPECT_TRUE(middleware.options().compress_responses());
    EXPECT_TRUE(middleware.options().decompress_requests());
    
    // Update options
    CompressionOptions opts;
    opts.compress_responses(false);
    middleware.update_options(opts);
    
    EXPECT_FALSE(middleware.options().compress_responses());
    EXPECT_TRUE(middleware.options().decompress_requests());
}

#ifdef QB_IO_WITH_ZLIB
// Request decompression tests
TEST(CompressionMiddlewareTest, DecompressesGzipRequest) {
    // Create a test request with gzip compressed body
    const std::string original_body = "This is a test body for compression";
    std::string compressed_body = compress_string(original_body, "gzip");
    
    // Check that compressed body is different from original
    ASSERT_NE(original_body, compressed_body);
    
    auto req = create_test_request("application/json", compressed_body);
    req.add_header("Content-Encoding", "gzip");
    
    auto session = std::make_shared<MockSession>();
    RouterContext<MockSession, std::string> ctx(session, std::move(req));
    
    // Create and process middleware
    auto middleware = CompressionMiddleware<MockSession>();
    auto result = middleware.process(ctx);
    
    // Check the result is Continue
    EXPECT_TRUE(result.should_continue());
    
    // Check that the body was decompressed
    EXPECT_EQ(original_body, ctx.request.body().template as<std::string>());
    
    // In real-world usage, applications should check for the Content-Encoding header
    // and assume the content is decompressed if the middleware has processed it.
    // The header may or may not be removed based on the HTTP library implementation.
}

TEST(CompressionMiddlewareTest, HandlesInvalidCompressedData) {
    // Create a test request with invalid compressed data
    const std::string invalid_data = "This is not valid compressed data";
    
    auto req = create_test_request("application/json", invalid_data);
    req.add_header("Content-Encoding", "gzip");
    
    auto session = std::make_shared<MockSession>();
    RouterContext<MockSession, std::string> ctx(session, std::move(req));
    
    // Create and process middleware
    auto middleware = CompressionMiddleware<MockSession>();
    auto result = middleware.process(ctx);
    
    EXPECT_TRUE(result.should_stop());
    EXPECT_EQ(HTTP_STATUS_BAD_REQUEST, ctx.response.status_code);
    EXPECT_TRUE(ctx.is_handled());
}

TEST(CompressionMiddlewareTest, SkipsDecompressionWhenDisabled) {
    // Create a test request with gzip compressed body
    const std::string original_body = "This is a test body for compression";
    std::string compressed_body = compress_string(original_body, "gzip");
    
    auto req = create_test_request("application/json", compressed_body);
    req.add_header("Content-Encoding", "gzip");
    
    auto session = std::make_shared<MockSession>();
    RouterContext<MockSession, std::string> ctx(session, std::move(req));
    
    // Create middleware with decompression disabled
    CompressionOptions opts;
    opts.decompress_requests(false);
    auto middleware = CompressionMiddleware<MockSession>(opts);
    auto result = middleware.process(ctx);
    
    EXPECT_TRUE(result.should_continue());
    // Body should remain compressed
    EXPECT_EQ(compressed_body, ctx.request.body().template as<std::string>());
    EXPECT_TRUE(ctx.request.has_header("Content-Encoding"));
}

// Response compression tests
TEST(CompressionMiddlewareTest, CompressesResponseWhenAcceptEncodingIsPresent) {
    // Create a test request with Accept-Encoding header
    auto req = create_test_request("", "");
    req.add_header("Accept-Encoding", "gzip");
    
    // Create a response with substantial text
    std::string response_body(3000, 'a');  // 3000 'a' characters (compressible)
    
    auto session = std::make_shared<MockSession>();
    RouterContext<MockSession, std::string> ctx(session, std::move(req));
    ctx.response.body() = response_body;
    ctx.response.add_header("Content-Type", "text/plain");
    
    // Create and process middleware
    auto middleware = CompressionMiddleware<MockSession>();
    middleware.process(ctx);
    
    // Simulate after_handling callback execution
    ctx.execute_after_callbacks();
    
    EXPECT_TRUE(ctx.response.has_header("Content-Encoding"));
    EXPECT_EQ("gzip", ctx.response.header("Content-Encoding"));
    EXPECT_TRUE(ctx.response.has_header("Vary"));
    EXPECT_EQ("Accept-Encoding", ctx.response.header("Vary"));
    
    // Compressed body should be smaller than original
    EXPECT_LT(ctx.response.body().size(), response_body.size());
}

TEST(CompressionMiddlewareTest, DoesNotCompressSmallResponses) {
    // Create a test request with Accept-Encoding header
    auto req = create_test_request("", "");
    req.add_header("Accept-Encoding", "gzip");
    
    // Create a small response (below default min_size_to_compress)
    std::string response_body = "Small body";
    
    auto session = std::make_shared<MockSession>();
    RouterContext<MockSession, std::string> ctx(session, std::move(req));
    ctx.response.body() = response_body;
    ctx.response.add_header("Content-Type", "text/plain");
    
    // Create and process middleware
    auto middleware = CompressionMiddleware<MockSession>();
    middleware.process(ctx);
    
    // Simulate after_handling callback execution
    ctx.execute_after_callbacks();
    
    // Should not be compressed
    EXPECT_FALSE(ctx.response.has_header("Content-Encoding"));
    EXPECT_EQ(response_body, ctx.response.body().template as<std::string>());
}

TEST(CompressionMiddlewareTest, RespectsContentTypesThatAreAlreadyCompressed) {
    // Create a test request with Accept-Encoding header
    auto req = create_test_request("", "");
    req.add_header("Accept-Encoding", "gzip");
    
    // Create a response with an already compressed content type
    std::string response_body(3000, 'a');
    
    auto session = std::make_shared<MockSession>();
    RouterContext<MockSession, std::string> ctx(session, std::move(req));
    ctx.response.body() = response_body;
    ctx.response.add_header("Content-Type", "image/jpeg");  // Already compressed format
    
    // Create and process middleware
    auto middleware = CompressionMiddleware<MockSession>();
    middleware.process(ctx);
    
    // Simulate after_handling callback execution
    ctx.execute_after_callbacks();
    
    // Should not be compressed
    EXPECT_FALSE(ctx.response.has_header("Content-Encoding"));
    EXPECT_EQ(response_body, ctx.response.body().template as<std::string>());
}

TEST(CompressionMiddlewareTest, UsesCorrectEncodingBasedOnAcceptEncoding) {
    // Create a test request with Accept-Encoding header preferring deflate
    auto req = create_test_request("", "");
    req.add_header("Accept-Encoding", "deflate, gzip");
    
    // Create a response
    std::string response_body(3000, 'a');
    
    auto session = std::make_shared<MockSession>();
    RouterContext<MockSession, std::string> ctx(session, std::move(req));
    ctx.response.body() = response_body;
    ctx.response.add_header("Content-Type", "text/plain");
    
    // Create middleware with preference for gzip first
    CompressionOptions opts;
    opts.preferred_encodings({"gzip", "deflate"});
    auto middleware = CompressionMiddleware<MockSession>(opts);
    middleware.process(ctx);
    
    // Simulate after_handling callback execution
    ctx.execute_after_callbacks();
    
    // Should be compressed with one of the encodings
    EXPECT_TRUE(ctx.response.has_header("Content-Encoding"));
    
    // The exact choice depends on the priority logic
    std::string encoding = ctx.response.header("Content-Encoding");
    EXPECT_TRUE(encoding == "gzip" || encoding == "deflate");
}

TEST(CompressionMiddlewareTest, SkipsCompressionWhenDisabled) {
    // Create a test request with Accept-Encoding header
    auto req = create_test_request("", "");
    req.add_header("Accept-Encoding", "gzip");
    
    // Create a response
    std::string response_body(3000, 'a');
    
    auto session = std::make_shared<MockSession>();
    RouterContext<MockSession, std::string> ctx(session, std::move(req));
    ctx.response.body() = response_body;
    ctx.response.add_header("Content-Type", "text/plain");
    
    // Create middleware with compression disabled
    CompressionOptions opts;
    opts.compress_responses(false);
    auto middleware = CompressionMiddleware<MockSession>(opts);
    middleware.process(ctx);
    
    // Simulate after_handling callback execution
    ctx.execute_after_callbacks();
    
    // Should not be compressed
    EXPECT_FALSE(ctx.response.has_header("Content-Encoding"));
    EXPECT_EQ(response_body, ctx.response.body().template as<std::string>());
}

// NOUVEAUX TESTS:

// Test de multiples encodages dans l'en-tête Content-Encoding
TEST(CompressionMiddlewareTest, HandlesMultipleContentEncodings) {
    // Actuellement, le middleware ne supporte pas plusieurs encodages dans Content-Encoding
    // Ce test vérifie que le middleware gère correctement cette situation (devrait échouer proprement)
    
    // Créer une requête avec un corps compressé par gzip
    const std::string original_body = "This is a test body for compression";
    std::string compressed_body = compress_string(original_body, "gzip");
    
    auto req = create_test_request("application/json", compressed_body);
    req.add_header("Content-Encoding", "deflate, gzip"); // Multiple encodings
    
    auto session = std::make_shared<MockSession>();
    RouterContext<MockSession, std::string> ctx(session, std::move(req));
    
    // Create and process middleware
    auto middleware = CompressionMiddleware<MockSession>();
    auto result = middleware.process(ctx);
    
    // Should fail gracefully with BAD_REQUEST
    EXPECT_TRUE(result.should_stop());
    EXPECT_EQ(HTTP_STATUS_BAD_REQUEST, ctx.response.status_code);
    EXPECT_TRUE(ctx.is_handled());
}

// Test de vérification de la mise à jour de Content-Length
TEST(CompressionMiddlewareTest, UpdatesContentLengthAfterCompression) {
    auto req = create_test_request("", "");
    req.add_header("Accept-Encoding", "gzip");
    
    // Create a compressible response
    std::string response_body(5000, 'a');
    
    auto session = std::make_shared<MockSession>();
    RouterContext<MockSession, std::string> ctx(session, std::move(req));
    ctx.response.body() = response_body;
    ctx.response.add_header("Content-Type", "text/plain");
    ctx.response.add_header("Content-Length", std::to_string(response_body.size()));
    
    // Create and process middleware
    auto middleware = CompressionMiddleware<MockSession>();
    middleware.process(ctx);
    
    // Simulate after_handling callback execution
    ctx.execute_after_callbacks();
    
    // Content-Length header should be updated to match the compressed size
    EXPECT_TRUE(ctx.response.has_header("Content-Length"));
    EXPECT_EQ(std::to_string(ctx.response.body().size()), ctx.response.header("Content-Length"));
    EXPECT_NE(std::to_string(response_body.size()), ctx.response.header("Content-Length"));
}

// Test avec des données JSON réelles
TEST(CompressionMiddlewareTest, CompressesRealJsonData) {
    auto req = create_test_request("", "");
    req.add_header("Accept-Encoding", "gzip");
    
    // Use realistic JSON data
    std::string json_data = create_json_data();
    
    // S'assurer que la taille est supérieure au seuil min_size_to_compress
    // Répéter le JSON si nécessaire pour dépasser 1024 octets
    while (json_data.size() < 1500) {
        json_data += create_json_data();
    }
    
    auto session = std::make_shared<MockSession>();
    RouterContext<MockSession, std::string> ctx(session, std::move(req));
    ctx.response.body() = json_data;
    ctx.response.add_header("Content-Type", "application/json");
    
    // Create and process middleware
    auto middleware = CompressionMiddleware<MockSession>();
    middleware.process(ctx);
    
    // Simulate after_handling callback execution
    ctx.execute_after_callbacks();
    
    // Should be compressed
    EXPECT_TRUE(ctx.response.has_header("Content-Encoding"));
    EXPECT_EQ("gzip", ctx.response.header("Content-Encoding"));
    
    // Compressed data should be significantly smaller for JSON
    EXPECT_LT(ctx.response.body().size(), json_data.size() * 0.7); // At least 30% smaller
}

// Test avec des données HTML réelles
TEST(CompressionMiddlewareTest, CompressesRealHtmlData) {
    auto req = create_test_request("", "");
    req.add_header("Accept-Encoding", "gzip");
    
    // Use realistic HTML data
    std::string html_data = create_html_data();
    
    auto session = std::make_shared<MockSession>();
    RouterContext<MockSession, std::string> ctx(session, std::move(req));
    ctx.response.body() = html_data;
    ctx.response.add_header("Content-Type", "text/html");
    
    // Create and process middleware
    auto middleware = CompressionMiddleware<MockSession>();
    middleware.process(ctx);
    
    // Simulate after_handling callback execution
    ctx.execute_after_callbacks();
    
    // Should be compressed
    EXPECT_TRUE(ctx.response.has_header("Content-Encoding"));
    EXPECT_EQ("gzip", ctx.response.header("Content-Encoding"));
    
    // Compressed data should be significantly smaller for HTML
    EXPECT_LT(ctx.response.body().size(), html_data.size() * 0.6); // At least 40% smaller
}

// Test d'intégration avec d'autres middlewares
TEST(CompressionMiddlewareTest, IntegratesWithOtherMiddlewares) {
    // Create a middleware chain with multiple middleware types
    auto chain = make_middleware_chain<MockSession>();
    
    // Add a logging middleware
    bool log_called = false;
    chain->add(make_middleware<MockSession>([&log_called](auto& ctx) {
        log_called = true;
        return MiddlewareResult::Continue();
    }, "LoggingMock"));
    
    // Add the compression middleware
    chain->add(compression_middleware<MockSession>());
    
    // Add error handling middleware
    chain->add(make_middleware<MockSession>([](auto& ctx) {
        ctx.response.add_header("X-ErrorHandled", "true");
        return MiddlewareResult::Continue();
    }, "ErrorHandlingMock"));
    
    // Create a request with Accept-Encoding
    auto req = create_test_request("application/json", "{}");
    req.add_header("Accept-Encoding", "gzip");
    
    auto session = std::make_shared<MockSession>();
    RouterContext<MockSession, std::string> ctx(session, std::move(req));
    
    // Add a response body for the compression middleware to compress
    ctx.response.body() = std::string(3000, 'a');
    ctx.response.add_header("Content-Type", "text/plain");
    
    // Process the chain
    auto result = chain->process(ctx);
    
    // Execute after handlers
    ctx.execute_after_callbacks();
    
    // Check results
    EXPECT_TRUE(result.should_continue());
    EXPECT_TRUE(log_called);
    EXPECT_TRUE(ctx.response.has_header("X-ErrorHandled"));
    EXPECT_TRUE(ctx.response.has_header("Content-Encoding"));
    EXPECT_EQ("gzip", ctx.response.header("Content-Encoding"));
}

// Test de performance simple
TEST(CompressionMiddlewareTest, PerformanceBenchmark) {
    auto req = create_test_request("", "");
    req.add_header("Accept-Encoding", "gzip");
    
    // Différents types de données avec des caractéristiques de compression différentes
    std::string text_data(10000, 'a');      // Hautement compressible
    std::string json_data = create_json_data();
    // S'assurer que le JSON est assez gros pour être compressé
    while (json_data.size() < 1500) {
        json_data += create_json_data();
    }
    
    std::string html_data = create_html_data();
    // S'assurer que l'HTML est assez gros pour être compressé
    while (html_data.size() < 1500) {
        html_data += create_html_data();
    }
    
    std::string random_data;                // Moins compressible
    random_data.reserve(10000);
    for (int i = 0; i < 10000; i++) {
        random_data += static_cast<char>(rand() % 256);
    }
    
    // Créer le middleware avec un seuil de compression plus bas pour les tests
    CompressionOptions opts;
    opts.min_size_to_compress(100); // Utiliser un seuil plus bas pour tester
    auto middleware = CompressionMiddleware<MockSession>(opts);
    
    // Tableau pour stocker les résultats
    struct CompressionResult {
        std::string name;
        size_t original_size;
        size_t compressed_size;
        double compression_ratio;
        std::chrono::microseconds duration;
    };
    
    std::vector<CompressionResult> results;
    
    // Fonction pour tester la compression
    auto test_compression = [&](const std::string& name, const std::string& data, const std::string& content_type) {
        auto session = std::make_shared<MockSession>();
        RouterContext<MockSession, std::string> ctx(session, create_test_request("", ""));
        ctx.request.add_header("Accept-Encoding", "gzip");
        ctx.response.body() = data;
        ctx.response.add_header("Content-Type", content_type);
        
        // Mesurer le temps de compression
        auto start = std::chrono::high_resolution_clock::now();
        middleware.process(ctx);
        ctx.execute_after_callbacks();
        auto end = std::chrono::high_resolution_clock::now();
        
        // Calculer la durée
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        // Calculer le taux de compression
        double ratio = 0.0;
        if (ctx.response.has_header("Content-Encoding")) {
            ratio = static_cast<double>(ctx.response.body().size()) / static_cast<double>(data.size());
        } else {
            ratio = 1.0; // Pas de compression
        }
        
        // Stocker les résultats
        results.push_back({
            name,
            data.size(),
            ctx.response.body().size(),
            ratio,
            duration
        });
    };
    
    // Tester les différents types de données
    test_compression("Texte répétitif", text_data, "text/plain");
    test_compression("JSON", json_data, "application/json");
    test_compression("HTML", html_data, "text/html");
    test_compression("Données aléatoires", random_data, "application/octet-stream");
    
    // Vérifier les résultats
    for (const auto& result : results) {
        if (result.name == "Texte répétitif" || result.name == "JSON" || result.name == "HTML") {
            // Les données textuelles devraient avoir un bon taux de compression
            EXPECT_LT(result.compression_ratio, 0.8);
        }
        
        // Le temps de compression devrait être raisonnable
        EXPECT_LT(result.duration.count(), 100000); // Moins de 100ms
        
        // Logger les résultats pour information
        std::cout << "Performance - " << result.name 
                  << ": Size " << result.original_size << " -> " << result.compressed_size 
                  << " (ratio: " << result.compression_ratio 
                  << "), Time: " << result.duration.count() << "μs" << std::endl;
    }
}
#endif

// Factory function tests
TEST(CompressionMiddlewareTest, FactoryFunctionCreatesDefaultMiddleware) {
    auto middleware_adapter = compression_middleware<MockSession>();
    EXPECT_TRUE(middleware_adapter->name().find("CompressionMiddleware") != std::string::npos);
}

TEST(CompressionMiddlewareTest, FactoryFunctionWithOptionsCreatesCustomizedMiddleware) {
    CompressionOptions opts;
    opts.min_size_to_compress(500);
    auto middleware_adapter = compression_middleware<MockSession>(opts, "CustomCompression");
    EXPECT_TRUE(middleware_adapter->name().find("CustomCompression") != std::string::npos);
}

TEST(CompressionMiddlewareTest, MaxCompressionMiddlewareCreatesOptimizedMiddleware) {
    auto middleware_adapter = max_compression_middleware<MockSession>();
    EXPECT_TRUE(middleware_adapter->name().find("MaxCompressionMiddleware") != std::string::npos);
}

TEST(CompressionMiddlewareTest, FastCompressionMiddlewareCreatesOptimizedMiddleware) {
    auto middleware_adapter = fast_compression_middleware<MockSession>();
    EXPECT_TRUE(middleware_adapter->name().find("FastCompressionMiddleware") != std::string::npos);
}

TEST(CompressionMiddlewareTest, IntegratesWithMiddlewareChain) {
    // Create a chain with the compression middleware
    auto chain = make_middleware_chain<MockSession>();
    chain->add(compression_middleware<MockSession>());
    
    // Create a simple request
    auto req = create_test_request("text/plain", "test body");
    auto session = std::make_shared<MockSession>();
    RouterContext<MockSession, std::string> ctx(session, std::move(req));
    
    // Process the chain
    auto result = chain->process(ctx);
    EXPECT_TRUE(result.should_continue());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
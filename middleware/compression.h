#pragma once

#include <memory>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>

// New Includes for qb::http routing system
#include "../routing/middleware.h" // Includes IMiddleware, Context, AsyncTaskResult
#include "../utility.h"            // For qb::http::utility::split_string, ::iequals
#include "../body.h"               // For qb::http::Body
#include "../request.h"            // For qb::http::TRequest
#include "../response.h"           // For qb::http::Response
#include "../types.h"              // For http_status constants

namespace qb::http {

/**
 * @brief Configuration options for HTTP content compression.
 *
 * Allows specifying whether to compress responses or decompress requests,
 * the minimum body size to consider for compression, and a list of preferred
 * encoding algorithms (e.g., "gzip", "deflate").
 */
class CompressionOptions {
private:
    bool _compress_responses;
    bool _decompress_requests;
    size_t _min_size_to_compress;
    std::vector<std::string> _preferred_encodings;

public:
    /**
     * @brief Default constructor.
     * Enables response compression and request decompression by default.
     * Sets minimum compression size to 1024 bytes and prefers "gzip", then "deflate".
     */
    CompressionOptions()
        : _compress_responses(true)
        , _decompress_requests(true)
        , _min_size_to_compress(1024)
        , _preferred_encodings({"gzip", "deflate"}) {}

    /** @brief Enables or disables compression of HTTP responses. */
    CompressionOptions& compress_responses(bool enable) {
        _compress_responses = enable;
        return *this;
    }

    /** @brief Enables or disables decompression of HTTP request bodies. */
    CompressionOptions& decompress_requests(bool enable) {
        _decompress_requests = enable;
        return *this;
    }

    /** @brief Sets the minimum size in bytes a response body must have to be considered for compression. */
    CompressionOptions& min_size_to_compress(size_t size) {
        _min_size_to_compress = size;
        return *this;
    }

    /** @brief Sets the list of preferred compression encodings, in order of preference. */
    CompressionOptions& preferred_encodings(const std::vector<std::string>& encodings) {
        _preferred_encodings = encodings;
        return *this;
    }

    /** 
     * @brief Provides a configuration optimized for higher compression ratios.
     * Typically compresses smaller bodies and may include more computationally intensive algorithms.
     */
    static CompressionOptions max_compression() {
        return CompressionOptions()
            .min_size_to_compress(256)
            .preferred_encodings({"gzip", "deflate", "br"}); // Note: "br" (Brotli) requires specific library support
    }

    /** 
     * @brief Provides a configuration optimized for faster compression speed.
     * Typically compresses only larger bodies and prefers faster algorithms like deflate.
     */
    static CompressionOptions fast_compression() {
        return CompressionOptions()
            .min_size_to_compress(2048)
            .preferred_encodings({"deflate", "gzip"});
    }

    // Getters
    [[nodiscard]] bool should_compress_responses() const { return _compress_responses; }
    [[nodiscard]] bool should_decompress_requests() const { return _decompress_requests; }
    [[nodiscard]] size_t get_min_size_to_compress() const { return _min_size_to_compress; }
    [[nodiscard]] const std::vector<std::string>& get_preferred_encodings() const { return _preferred_encodings; }
};

/**
 * @brief Middleware for automatic request decompression and response compression.
 *
 * This middleware inspects `Content-Encoding` for requests and `Accept-Encoding` 
 * for responses to apply or remove compression (e.g., gzip, deflate) as configured.
 * Requires `QB_IO_WITH_ZLIB` to be defined for actual compression operations.
 * 
 * @tparam SessionType The type of the session object managed by the router.
 */
template <typename SessionType>
class CompressionMiddleware : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;
    // TRequest will be ctx->request(), which is qb::http::Request (TRequest<std::string>)
    // TResponse will be ctx->response(), which is qb::http::Response

    /**
     * @brief Constructs CompressionMiddleware with default options.
     * @param name An optional name for this middleware instance.
     */
    explicit CompressionMiddleware(std::string name = "CompressionMiddleware")
        : _options()
        , _name(std::move(name)) {}

    /**
     * @brief Constructs CompressionMiddleware with specified options.
     * @param options The compression options to use.
     * @param name An optional name for this middleware instance.
     */
    CompressionMiddleware(const CompressionOptions& options, 
                          std::string name = "CompressionMiddleware")
        : _options(options)
        , _name(std::move(name)) {}

    /**
     * @brief Handles the request: decompresses request body if applicable and sets up
     *        a lifecycle hook for response body compression.
     * @param ctx The shared context for the current request.
     */
    void process(ContextPtr ctx) override {
#ifdef QB_IO_WITH_ZLIB
        if (_options.should_decompress_requests() && can_decompress_request(ctx->request())) {
            try {
                decompress_request_body(ctx->request());
            } catch (const std::runtime_error& e) {
                ctx->response().status_code = HTTP_STATUS_BAD_REQUEST;
                ctx->response().body() = std::string("Invalid compressed data: ") + e.what();
                ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                ctx->complete(AsyncTaskResult::COMPLETE);
                return;
            } catch (const std::exception& e) {
                ctx->response().status_code = HTTP_STATUS_BAD_REQUEST;
                ctx->response().body() = std::string("Error during request decompression: ") + e.what();
                ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                ctx->complete(AsyncTaskResult::COMPLETE);
                return;
            }
        }

        if (_options.should_compress_responses()) {
            // Add a PRE_RESPONSE_SEND hook for response compression
            ctx->add_lifecycle_hook([this](Context<SessionType>& ctx_ref, HookPoint point) {
                if (point == HookPoint::PRE_RESPONSE_SEND) {
                    if (!ctx_ref.response().body().empty()) {
                        compress_response_body(ctx_ref);
                    }
                }
            });
        }
#endif
        ctx->complete(AsyncTaskResult::CONTINUE);
    }

    /** @brief Gets the name of this middleware instance. */
    std::string name() const override {
        return _name;
    }
    
    /** @brief Handles cancellation; a no-op for this synchronous middleware. */
    void cancel() override {}

    /** @brief Updates the compression options for this middleware instance. */
    void update_options(const CompressionOptions& opts) {
        _options = opts;
    }
    /** @brief Gets the current compression options. */
    const CompressionOptions& get_options() const {
        return _options;
    }

private:
    CompressionOptions _options;
    std::string _name;

    /** @brief Checks if the request indicates it has a compressed body that can be decompressed. */
    bool can_decompress_request(const Request& request) const {
        return request.has_header("Content-Encoding");
    }

    /** @brief Decompresses the request body in-place. */
    void decompress_request_body(Request& request) {
#ifdef QB_IO_WITH_ZLIB
        // Ensure encoding is a std::string for Body::uncompress
        std::string encoding = std::string(request.header("Content-Encoding"));
        
        if (request.body().empty() || encoding.empty()) {
            return;
        }
        
        try {
            request.body().uncompress(encoding);
            
            // Remove Content-Encoding header after successful decompression
            request.headers().erase("Content-Encoding");
            if (request.has_header("Content-Length")) {
                request.set_header("Content-Length", std::to_string(request.body().size()));
            }
        } catch (const std::runtime_error& e) {
            throw std::runtime_error(std::string("Decompression failed: ") + e.what());
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("Generic error during decompression attempt: ") + e.what());
        }
#endif
    }

    /** @brief Compresses the response body in-place if conditions are met. */
    void compress_response_body(Context<SessionType>& ctx_ref) { 
#ifdef QB_IO_WITH_ZLIB
        if (ctx_ref.response().body().size() < _options.get_min_size_to_compress() ||
            ctx_ref.response().has_header("Content-Encoding") ||
            is_precompressed_content_type(std::string(ctx_ref.response().header("Content-Type")))) {
            return;
        }

        std::string encoding = select_best_encoding(ctx_ref.request());
        if (encoding.empty()) {
            return;
        }

        if (ctx_ref.response().body().size() < _options.get_min_size_to_compress()) {
            return;
        }

        auto compressed_size = ctx_ref.response().body().compress(encoding);
        if (compressed_size > 0) {
            ctx_ref.response().set_header("Content-Encoding", encoding);
            ctx_ref.response().set_header("Vary", "Accept-Encoding"); 
            ctx_ref.response().set_header("Content-Length", std::to_string(compressed_size));
        }
#endif
    }

    /** @brief Selects the best encoding based on request's Accept-Encoding and middleware options. */
    std::string select_best_encoding(const Request& request) const {
        std::string accept_encoding_header = std::string(request.header("Accept-Encoding"));
        if (accept_encoding_header.empty()) {
            return "";
        }

        auto accepted_encodings = utility::split_string<std::string>(accept_encoding_header, ",");
        for (auto& encoding_entry : accepted_encodings) {
            size_t q_pos = encoding_entry.find(';');
            if (q_pos != std::string::npos) {
                encoding_entry = encoding_entry.substr(0, q_pos);
            }
            // Trim whitespace (basic)
            encoding_entry.erase(0, encoding_entry.find_first_not_of(" \t"));
            encoding_entry.erase(encoding_entry.find_last_not_of(" \t") + 1);
        }

        for (const auto& preferred_encoding : _options.get_preferred_encodings()) {
            if (std::find_if(accepted_encodings.begin(), accepted_encodings.end(),
                            [&preferred_encoding](const std::string& accepted_e) {
                                return utility::iequals(accepted_e, preferred_encoding) || accepted_e == "*";
                            }) != accepted_encodings.end()) {
                return preferred_encoding;
            }
        }
        return "";
    }

    /** @brief Checks if a MIME type is typically already compressed (e.g., JPEG, PDF). */
    bool is_precompressed_content_type(const std::string& content_type_header) const {
        static const std::vector<std::string> compressed_types = {
            "image/jpeg", "image/png", "image/gif", "image/webp",
            "audio/mp3", "audio/mpeg", "audio/ogg", "audio/aac",
            "video/mp4", "video/mpeg", "video/webm",
            "application/zip", "application/gzip", "application/x-rar-compressed",
            "application/x-7z-compressed", "application/x-bzip2", "application/pdf"
        };
        std::string main_type = content_type_header;
        size_t semicolon_pos = main_type.find(';');
        if (semicolon_pos != std::string::npos) {
            main_type = main_type.substr(0, semicolon_pos);
            // Basic trim for comparison
            size_t end_pos = main_type.find_last_not_of(" \t");
            if (std::string::npos != end_pos ) {
                main_type = main_type.substr( 0, end_pos + 1 );
            }
        }

        for (const auto& type : compressed_types) {
            if (utility::iequals(main_type, type)) { 
                return true;
            }
        }
        return false;
    }
};

/**
 * @brief Creates a CompressionMiddleware instance with specified or default options.
 * @tparam SessionType The session type.
 * @param options Compression options.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created CompressionMiddleware.
 */
template <typename SessionType>
std::shared_ptr<CompressionMiddleware<SessionType>>
compression_middleware(
    const CompressionOptions& options = CompressionOptions(),
    const std::string& name = "CompressionMiddleware"
) {
    return std::make_shared<CompressionMiddleware<SessionType>>(options, name);
}

/**
 * @brief Creates a CompressionMiddleware instance configured for maximum compression.
 * @tparam SessionType The session type.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created CompressionMiddleware.
 */
template <typename SessionType>
std::shared_ptr<CompressionMiddleware<SessionType>>
max_compression_middleware(const std::string& name = "MaxCompressionMiddleware") {
    auto options = CompressionOptions::max_compression();
    return std::make_shared<CompressionMiddleware<SessionType>>(options, name);
}

/**
 * @brief Creates a CompressionMiddleware instance configured for fast compression.
 * @tparam SessionType The session type.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created CompressionMiddleware.
 */
template <typename SessionType>
std::shared_ptr<CompressionMiddleware<SessionType>>
fast_compression_middleware(const std::string& name = "FastCompressionMiddleware") {
    auto options = CompressionOptions::fast_compression();
    return std::make_shared<CompressionMiddleware<SessionType>>(options, name);
}

} // namespace qb::http 
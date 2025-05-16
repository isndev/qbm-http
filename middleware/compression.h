#pragma once

#include <memory>
#include <string>
#include <vector>
#include <algorithm>
#include "./middleware_interface.h"
#include "../utility.h"
#include "../body.h"

namespace qb::http {

/**
 * @brief Compression configuration options
 */
class CompressionOptions {
private:
    bool _compress_responses;
    bool _decompress_requests;
    size_t _min_size_to_compress;
    std::vector<std::string> _preferred_encodings;

public:
    /**
     * @brief Default constructor with common settings
     */
    CompressionOptions()
        : _compress_responses(true)
        , _decompress_requests(true)
        , _min_size_to_compress(1024) // Don't compress small bodies by default
        , _preferred_encodings({"gzip", "deflate"}) {}

    /**
     * @brief Enable/disable response compression
     * @param enable Whether to compress responses
     * @return Reference to this options object
     */
    CompressionOptions& compress_responses(bool enable) {
        _compress_responses = enable;
        return *this;
    }

    /**
     * @brief Enable/disable request decompression
     * @param enable Whether to decompress requests
     * @return Reference to this options object
     */
    CompressionOptions& decompress_requests(bool enable) {
        _decompress_requests = enable;
        return *this;
    }

    /**
     * @brief Set the minimum size (in bytes) for bodies to be compressed
     * @param size Minimum size in bytes
     * @return Reference to this options object
     */
    CompressionOptions& min_size_to_compress(size_t size) {
        _min_size_to_compress = size;
        return *this;
    }

    /**
     * @brief Set the preferred compression encodings in order of preference
     * @param encodings List of encoding names (e.g., "gzip", "deflate", "br")
     * @return Reference to this options object
     */
    CompressionOptions& preferred_encodings(const std::vector<std::string>& encodings) {
        _preferred_encodings = encodings;
        return *this;
    }

    /**
     * @brief Static factory method for maximum compression
     * @return CompressionOptions with high compression settings
     */
    static CompressionOptions max_compression() {
        return CompressionOptions()
            .min_size_to_compress(256)  // Compress even small responses
            .preferred_encodings({"gzip", "deflate", "br"});
    }

    /**
     * @brief Static factory method for fast compression
     * @return CompressionOptions with fast compression settings
     */
    static CompressionOptions fast_compression() {
        return CompressionOptions()
            .min_size_to_compress(2048)  // Only compress larger responses
            .preferred_encodings({"deflate", "gzip"});  // Deflate is faster
    }

    // Getters
    [[nodiscard]] bool compress_responses() const { return _compress_responses; }
    [[nodiscard]] bool decompress_requests() const { return _decompress_requests; }
    [[nodiscard]] size_t min_size_to_compress() const { return _min_size_to_compress; }
    [[nodiscard]] const std::vector<std::string>& preferred_encodings() const { return _preferred_encodings; }
};

/**
 * @brief Middleware for handling HTTP content compression/decompression
 * 
 * This middleware provides:
 * 1. Automatic compression of responses based on Accept-Encoding header
 * 2. Automatic decompression of requests with Content-Encoding header
 * 
 * The middleware will:
 * - Only compress responses if Accept-Encoding matches supported algorithms
 * - Only compress responses above a configurable minimum size
 * - Skip compression for already-compressed content types (images, videos, etc.)
 * - Automatically decompress request bodies for easier handling
 * - Add appropriate Vary headers
 * 
 * @tparam Session Session type
 * @tparam String String type (defaults to std::string)
 */
template <typename Session, typename String = std::string>
class CompressionMiddleware : public ISyncMiddleware<Session, String> {
public:
    using Context = typename ISyncMiddleware<Session, String>::Context;

    /**
     * @brief Construct with default options
     * @param name Middleware name
     */
    explicit CompressionMiddleware(std::string name = "CompressionMiddleware")
        : _options()
        , _name(std::move(name)) {}

    /**
     * @brief Construct with specified options
     * @param options Compression options
     * @param name Middleware name
     */
    CompressionMiddleware(const CompressionOptions& options, 
                          std::string name = "CompressionMiddleware")
        : _options(options)
        , _name(std::move(name)) {}

    /**
     * @brief Process the request/response for compression/decompression
     * @param ctx Request context
     * @return MiddlewareResult indicating whether to continue processing
     */
    MiddlewareResult process(Context& ctx) override {
#ifdef QB_IO_WITH_ZLIB
        // Step 1: Decompress request if needed
        if (_options.decompress_requests() && should_decompress_request(ctx.request)) {
            try {
                decompress_request(ctx);
            } catch (const std::exception& e) {
                // If decompression fails, return 400 Bad Request
                ctx.response.status_code = HTTP_STATUS_BAD_REQUEST;
                ctx.response.body() = std::string("Invalid compressed data: ") + e.what();
                ctx.mark_handled();
                return MiddlewareResult::Stop();
            }
        }

        // Step 2: Set up response compression if needed
        if (_options.compress_responses()) {
            // Register an after handler to compress the response after processing
            ctx.after_handling([this](Context& ctx) {
                if (!ctx.response.body().empty()) {
                    compress_response(ctx);
                }
            });
        }
#endif
        return MiddlewareResult::Continue();
    }

    /**
     * @brief Get the middleware name
     * @return Middleware name
     */
    std::string name() const override {
        return _name;
    }

    /**
     * @brief Update the compression options
     * @param options New compression options
     */
    void update_options(const CompressionOptions& options) {
        _options = options;
    }

    /**
     * @brief Get the current compression options
     * @return Current compression options
     */
    const CompressionOptions& options() const {
        return _options;
    }

private:
    CompressionOptions _options;
    std::string _name;

    /**
     * @brief Check if a request should be decompressed
     * @param request HTTP request
     * @return true if request should be decompressed
     */
    bool should_decompress_request(const TRequest<String>& request) const {
        // Check if request has Content-Encoding header
        return request.has_header("Content-Encoding");
    }

    /**
     * @brief Decompress the request body
     * @param ctx Request context
     */
    void decompress_request(Context& ctx) {
#ifdef QB_IO_WITH_ZLIB
        const std::string& encoding = ctx.request.header("Content-Encoding");
        
        if (ctx.request.body().empty()) {
            return; // Nothing to decompress
        }

        // Uncompress the body using the Body class's method
        ctx.request.body().uncompress(encoding);
        
        // Remove the Content-Encoding header since we've decompressed it
        // Use erase instead of remove_header to ensure it's actually removed
        auto& headers = ctx.request.headers();
        headers.erase("Content-Encoding");
        
        // Update Content-Length if present
        if (ctx.request.has_header("Content-Length")) {
            ctx.request.set_header("Content-Length", std::to_string(ctx.request.body().size()));
        }
#endif
    }

    /**
     * @brief Compress the response body
     * @param ctx Request context
     */
    void compress_response(Context& ctx) {
#ifdef QB_IO_WITH_ZLIB
        // Don't compress if:
        // 1. Body is smaller than minimum size
        // 2. Response is already compressed (has Content-Encoding)
        // 3. Content type is already compressed format
        if (ctx.response.body().size() < _options.min_size_to_compress() ||
            ctx.response.has_header("Content-Encoding") ||
            is_precompressed_content_type(ctx.response.header("Content-Type"))) {
            return;
        }

        // Check if client accepts compression
        std::string encoding = select_best_encoding(ctx.request);
        if (encoding.empty()) {
            return; // No compatible encoding found
        }

        // Save original size for comparison
        auto original_size = ctx.response.body().size();
        
        // Compress the body
        auto compressed_size = ctx.response.body().compress(encoding);

        // Only use compression if it reduced the size
        if (compressed_size < original_size) {
            // Update headers
            ctx.response.add_header("Content-Encoding", encoding);
            ctx.response.add_header("Vary", "Accept-Encoding");
        } else {
            // If compression didn't help, revert to original
            ctx.response.body().uncompress(encoding);
        }
#endif
    }

    /**
     * @brief Select the best encoding based on client's Accept-Encoding
     * @param request HTTP request
     * @return Selected encoding name or empty string if none supported
     */
    std::string select_best_encoding(const TRequest<String>& request) const {
        std::string accept_encoding = request.header("Accept-Encoding");
        if (accept_encoding.empty()) {
            return ""; // Client doesn't accept any encoding
        }

        // Parse Accept-Encoding header using utility function
        auto accepted_encodings = utility::split_string<std::string>(accept_encoding, ",");
        for (auto& encoding : accepted_encodings) {
            // Strip whitespace and quality value if present
            size_t q_pos = encoding.find(';');
            if (q_pos != std::string::npos) {
                encoding = encoding.substr(0, q_pos);
            }
            // Trim whitespace
            encoding.erase(0, encoding.find_first_not_of(" \t"));
            encoding.erase(encoding.find_last_not_of(" \t") + 1);
        }

        // Find the first preferred encoding that's accepted by the client
        for (const auto& encoding : _options.preferred_encodings()) {
            if (std::find_if(accepted_encodings.begin(), accepted_encodings.end(),
                            [&encoding](const std::string& e) {
                                return utility::iequals(e, encoding) || e == "*";
                            }) != accepted_encodings.end()) {
                return encoding;
            }
        }

        return ""; // No matching encoding found
    }

    /**
     * @brief Check if a content type is typically already compressed
     * @param content_type Content type to check
     * @return true if content type is typically pre-compressed
     */
    bool is_precompressed_content_type(const std::string& content_type) const {
        // List of content types that are typically already compressed
        static const std::vector<std::string> compressed_types = {
            "image/jpeg", "image/png", "image/gif", "image/webp",
            "audio/mp3", "audio/mpeg", "audio/ogg", "audio/aac",
            "video/mp4", "video/mpeg", "video/webm",
            "application/zip", "application/gzip", "application/x-rar-compressed",
            "application/x-7z-compressed", "application/x-bzip2", "application/pdf"
        };

        // Check if content type matches any known compressed format
        for (const auto& type : compressed_types) {
            if (content_type.find(type) == 0) {
                return true;
            }
        }

        return false;
    }
};

/**
 * @brief Factory function to create a compression middleware with default options
 * @tparam Session Session type
 * @tparam String String type
 * @param options Compression options
 * @param name Middleware name
 * @return Shared pointer to middleware adapter
 */
template <typename Session, typename String = std::string>
auto compression_middleware(
    const CompressionOptions& options = CompressionOptions(),
    const std::string& name = "CompressionMiddleware"
) {
    auto middleware = std::make_shared<CompressionMiddleware<Session, String>>(options, name);
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(middleware);
}

/**
 * @brief Factory function to create a compression middleware with maximum compression
 * @tparam Session Session type
 * @tparam String String type
 * @return Shared pointer to middleware adapter
 */
template <typename Session, typename String = std::string>
auto max_compression_middleware() {
    auto options = CompressionOptions::max_compression();
    auto middleware = std::make_shared<CompressionMiddleware<Session, String>>(
        options, "MaxCompressionMiddleware");
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(middleware);
}

/**
 * @brief Factory function to create a compression middleware with fast compression
 * @tparam Session Session type
 * @tparam String String type
 * @return Shared pointer to middleware adapter
 */
template <typename Session, typename String = std::string>
auto fast_compression_middleware() {
    auto options = CompressionOptions::fast_compression();
    auto middleware = std::make_shared<CompressionMiddleware<Session, String>>(
        options, "FastCompressionMiddleware");
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(middleware);
}

} // namespace qb::http 
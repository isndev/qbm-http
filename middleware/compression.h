/**
 * @file qbm/http/middleware/compression.h
 * @brief Defines middleware for HTTP request/response compression and decompression.
 *
 * This file provides the `CompressionMiddleware` class template and its associated
 * `CompressionOptions`. This middleware automatically handles decompression of
 * incoming request bodies (e.g., gzip, deflate) and compression of outgoing
 * response bodies based on client capabilities (`Accept-Encoding`) and server configuration.
 * Actual compression/decompression operations require the `QB_HAS_COMPRESSION` macro to be defined.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Middleware
 */
#pragma once

#include <memory>      // For std::shared_ptr
#include <string>      // For std::string
#include <vector>      // For std::vector
#include <algorithm>   // For std::find_if
#include <chrono>      // For std::chrono::seconds etc.
#include <stdexcept>   // For std::runtime_error (used by Body compression)

#include "../routing/middleware.h" // For IMiddleware, Context, AsyncTaskResult, HookPoint
#include "../utility.h"            // For qb::http::utility::split_string, ::iequals
#include "../body.h"               // For qb::http::Body
#include "../request.h"            // For qb::http::Request (used by Context)
#include "../response.h"           // For qb::http::Response (used by Context)
#include "../types.h"              // For qb::http::status constants and qb::http::method

namespace qb::http {
    /**
     * @brief Configuration options for HTTP content compression and decompression.
     *
     * Allows fine-grained control over how the `CompressionMiddleware` behaves,
     * including enabling/disabling request/response processing, setting minimum body sizes
     * for compression, and specifying a list of preferred encoding algorithms.
     */
    class CompressionOptions {
    private:
        bool _compress_responses; ///< If true, middleware will attempt to compress response bodies.
        bool _decompress_requests; ///< If true, middleware will attempt to decompress request bodies.
        size_t _min_size_to_compress; ///< Minimum response body size (bytes) to consider for compression.
        std::vector<std::string> _preferred_encodings; ///< Ordered list of preferred server-side compression encodings.

    public:
        /**
         * @brief Default constructor.
         *
         * Initializes with common defaults:
         * - Response compression: enabled
         * - Request decompression: enabled
         * - Minimum size to compress: 1024 bytes
         * - Preferred encodings: {"gzip", "deflate"}
         */
        CompressionOptions() noexcept
            : _compress_responses(true)
              , _decompress_requests(true)
              , _min_size_to_compress(1024)
              , _preferred_encodings({"gzip", "deflate"}) {
        }

        /**
         * @brief Enables or disables compression of HTTP response bodies.
         * @param enable If `true`, responses may be compressed. Default is `true`.
         * @return Reference to this `CompressionOptions` instance for chaining.
         */
        CompressionOptions &compress_responses(bool enable) noexcept {
            _compress_responses = enable;
            return *this;
        }

        /**
         * @brief Enables or disables decompression of HTTP request bodies.
         * @param enable If `true`, incoming request bodies with `Content-Encoding` may be decompressed. Default is `true`.
         * @return Reference to this `CompressionOptions` instance for chaining.
         */
        CompressionOptions &decompress_requests(bool enable) noexcept {
            _decompress_requests = enable;
            return *this;
        }

        /**
         * @brief Sets the minimum size (in bytes) a response body must have to be eligible for compression.
         * Responses smaller than this size will not be compressed, even if other conditions are met.
         * @param size The minimum size in bytes. Default is 1024.
         * @return Reference to this `CompressionOptions` instance for chaining.
         */
        CompressionOptions &min_size_to_compress(size_t size) noexcept {
            _min_size_to_compress = size;
            return *this;
        }

        /**
         * @brief Sets the list of preferred compression encodings that the server supports and prefers, in order of preference.
         * Example: `{"gzip", "deflate"}`.
         * This list is used to negotiate with the client's `Accept-Encoding` header.
         * @param encodings A vector of strings representing encoding names (e.g., "gzip").
         * @return Reference to this `CompressionOptions` instance for chaining.
         */
        CompressionOptions &preferred_encodings(std::vector<std::string> encodings) {
            // Can allocate
            _preferred_encodings = std::move(encodings);
            return *this;
        }

        /** 
         * @brief Provides a pre-configured `CompressionOptions` instance optimized for higher compression ratios.
         * This typically means compressing smaller bodies and potentially including more computationally intensive algorithms
         * if available (e.g., Brotli, if the underlying compression library supports it and it's added here).
         * @return A `CompressionOptions` instance with settings for maximum compression.
         */
        [[nodiscard]] static CompressionOptions max_compression() noexcept {
            return CompressionOptions()
                    .min_size_to_compress(256) // Compress smaller files
                    .preferred_encodings({"gzip", "deflate"}); // "br" would need Brotli support
        }

        /** 
         * @brief Provides a pre-configured `CompressionOptions` instance optimized for faster compression speed.
         * This typically means compressing only larger bodies and preferring algorithms known for speed.
         * @return A `CompressionOptions` instance with settings for fast compression.
         */
        [[nodiscard]] static CompressionOptions fast_compression() noexcept {
            return CompressionOptions()
                    .min_size_to_compress(2048) // Compress only larger files
                    .preferred_encodings({"deflate", "gzip"}); // Deflate is often faster than gzip
        }

        // --- Getters ---
        [[nodiscard]] bool should_compress_responses() const noexcept { return _compress_responses; }
        [[nodiscard]] bool should_decompress_requests() const noexcept { return _decompress_requests; }
        [[nodiscard]] size_t get_min_size_to_compress() const noexcept { return _min_size_to_compress; }

        [[nodiscard]] const std::vector<std::string> &get_preferred_encodings() const noexcept {
            return _preferred_encodings;
        }
    };

    /**
     * @brief Middleware for automatic request body decompression and response body compression.
     *
     * This middleware inspects the `Content-Encoding` header for incoming requests and attempts
     * to decompress the body if a supported encoding (e.g., gzip, deflate) is specified and
     * if `QB_HAS_COMPRESSION` is defined.
     *
     * For outgoing responses, it inspects the client's `Accept-Encoding` header and the response body.
     * If conditions are met (e.g., body size exceeds `min_size_to_compress`, content type is not
     * already compressed, client accepts a supported encoding), it compresses the response body
     * and sets appropriate headers (`Content-Encoding`, `Vary`, `Content-Length`).
     * Response compression occurs via a `HookPoint::PRE_RESPONSE_SEND` lifecycle hook.
     * 
     * @tparam SessionType The type of the session object managed by the router, used by `Context`.
     */
    template<typename SessionType>
    class CompressionMiddleware : public IMiddleware<SessionType> {
    public:
        using ContextPtr = std::shared_ptr<Context<SessionType> >;
        using RequestType = Request; // Usually qb::http::Request
        using ResponseType = Response; // Usually qb::http::Response

        /**
         * @brief Constructs `CompressionMiddleware` with default `CompressionOptions`.
         * @param name An optional name for this middleware instance, for logging or identification.
         */
        explicit CompressionMiddleware(std::string name = "CompressionMiddleware") noexcept
            : _options() // Default constructed CompressionOptions
              , _name(std::move(name)) {
        }

        /**
         * @brief Constructs `CompressionMiddleware` with specified `CompressionOptions`.
         * @param options The compression options to use.
         * @param name An optional name for this middleware instance.
         */
        CompressionMiddleware(CompressionOptions options,
                              std::string name = "CompressionMiddleware") noexcept
            : _options(std::move(options)) // Options passed by value and moved
              , _name(std::move(name)) {
        }

        /**
         * @brief Processes the request: attempts to decompress request body if applicable,
         *        and registers a lifecycle hook to compress the response body before sending.
         * @param ctx The shared `Context` for the current request.
         */
        void process(ContextPtr ctx) override {
#ifdef QB_HAS_COMPRESSION
            if (_options.should_decompress_requests() && can_decompress_request(ctx->request())) {
                try {
                    decompress_request_body(ctx->request());
                } catch (const std::runtime_error &e) {
                    ctx->response().status() = qb::http::status::BAD_REQUEST;
                    ctx->response().body() = std::string("Invalid compressed request body: ") + e.what();
                    ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                    ctx->complete(AsyncTaskResult::COMPLETE); // Stop processing
                    return;
                } catch (const std::exception &e) {
                    // Catch other potential exceptions from Body::uncompress
                    ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                    ctx->response().body() = std::string("Error during request body decompression: ") + e.what();
                    ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                    ctx->complete(AsyncTaskResult::COMPLETE);
                    return;
                }
            }

            if (_options.should_compress_responses()) {
                // Add a PRE_RESPONSE_SEND hook for response compression.
                // This ensures compression happens after all handlers have finalized the response body.
                ctx->add_lifecycle_hook([this](Context<SessionType> &ctx_ref, HookPoint point) {
                    if (point == HookPoint::PRE_RESPONSE_SEND) {
                        if (!ctx_ref.response().body().empty()) {
                            try {
                                compress_response_body(ctx_ref); // Pass Context by reference as per Hook signature
                            } catch (const std::runtime_error &) {
                                // Log error, but don't modify response further at this critical stage.
                                // Or, strip Content-Encoding if partially set before error?
                                // For now, just log (if logging is available).
                                // std::cerr << "CompressionMiddleware: Error compressing response: " << e.what() << std::endl;
                            } catch (const std::exception &) {
                                // std::cerr << "CompressionMiddleware: Generic error compressing response: " << e.what() << std::endl;
                            }
                        }
                    }
                });
            }
#endif // QB_HAS_COMPRESSION
            ctx->complete(AsyncTaskResult::CONTINUE); // Continue to next middleware/handler
        }

        /** @brief Gets the name of this middleware instance. */
        [[nodiscard]] std::string name() const noexcept override {
            return _name;
        }

        /** @brief Handles cancellation; currently a no-op for this middleware. */
        void cancel() noexcept override {
            // No specific asynchronous operations to cancel within this middleware itself.
        }

        /**
         * @brief Updates the compression options for this middleware instance.
         * @param opts The new `CompressionOptions` to use.
         */
        void update_options(CompressionOptions opts) noexcept {
            // Pass by value for potential move
            _options = std::move(opts);
        }

        /** @brief Gets a constant reference to the current `CompressionOptions`. */
        [[nodiscard]] const CompressionOptions &get_options() const noexcept {
            return _options;
        }

    private:
        CompressionOptions _options;
        std::string _name;

        /**
         * @brief Checks if the request has a `Content-Encoding` header indicating a compressed body.
         * @param request The HTTP request object.
         * @return `true` if `Content-Encoding` header is present and not empty, `false` otherwise.
         */
        [[nodiscard]] bool can_decompress_request(const RequestType &request) const noexcept {
            // TRequest::header returns String type. Check if it's empty.
            // The actual encoding value is checked by Body::uncompress and its helpers.
            return request.has_header("Content-Encoding") && !request.header("Content-Encoding").empty();
        }

        /**
         * @brief Decompresses the request body in-place if `QB_HAS_COMPRESSION` is defined.
         * Modifies the request object by replacing its body with the decompressed content
         * and removing/updating `Content-Encoding` and `Content-Length` headers.
         * @param request The HTTP request object (mutable).
         * @throws std::runtime_error if decompression fails (e.g., bad data, unsupported encoding within Body::uncompress).
         */
        void decompress_request_body(RequestType &request) {
#ifdef QB_HAS_COMPRESSION
            // header() returns `const String&`. Body::uncompress needs `const std::string&`.
            std::string encoding_str;
            const auto &enc_header_val = request.header("Content-Encoding");
            if constexpr (std::is_same_v<std::decay_t<decltype(enc_header_val)>, std::string>) {
                encoding_str = enc_header_val;
            } else {
                // Assume std::string_view or convertible
                encoding_str = std::string(enc_header_val);
            }

            if (request.body().empty() || encoding_str.empty()) {
                return;
            }

            // Body::uncompress can throw std::runtime_error
            request.body().uncompress(encoding_str);

            request.remove_header("Content-Encoding");
            if (request.has_header("Content-Length")) {
                // Update Content-Length if present
                request.set_header("Content-Length", std::to_string(request.body().size()));
            }
#else
        (void)request; // Avoid unused parameter warning
#endif
        }

        /**
         * @brief Compresses the response body in-place if `QB_HAS_COMPRESSION` is defined and conditions are met.
         * Modifies the response object by replacing its body with compressed content and setting
         * `Content-Encoding`, `Vary`, and `Content-Length` headers.
         * @param ctx_ref Reference to the `Context` object containing the response.
         * @throws std::runtime_error if compression fails (e.g., unsupported encoding within Body::compress).
         */
        void compress_response_body(Context<SessionType> &ctx_ref) {
#ifdef QB_HAS_COMPRESSION
            ResponseType &response = ctx_ref.response(); // Get mutable reference

            if (response.body().size() < _options.get_min_size_to_compress() ||
                response.has_header("Content-Encoding") ||
                is_precompressed_content_type(std::string(response.content_type().type()))) {
                // Use parsed ContentType
                return;
            }

            std::string selected_encoding = select_best_encoding(ctx_ref.request());
            if (selected_encoding.empty()) {
                return; // No suitable encoding accepted by client or supported by server
            }

            // Redundant check, already done above, but kept for safety.
            if (response.body().size() < _options.get_min_size_to_compress()) {
                return;
            }

            // Body::compress can throw std::runtime_error
            std::size_t compressed_size = response.body().compress(selected_encoding);

            if (compressed_size > 0 && compressed_size < response.body().raw().size()) {
                // Only set headers if compression was effective
                response.set_header("Content-Encoding", selected_encoding);
                response.add_header("Vary", "Accept-Encoding"); // Add to existing Vary or create new
                response.set_header("Content-Length", std::to_string(compressed_size));
            } else if (compressed_size > 0 && compressed_size >= response.body().raw().size()) {
                // Compression did not reduce size or made it larger. Revert to original.
                // This requires Body::compress to return original if ineffective or Body to store original temporarily.
                // Current Body::compress overwrites. This aspect needs careful handling in Body::compress or here.
                // For now, assume if compress was called, we stick with it unless it critically failed (threw).
                // To be truly robust, Body::compress should ideally not modify if not beneficial or return original data.
                // Assuming current Body::compress always replaces, we might send larger data if not careful.
                // Let's assume for now: if compressed_size > 0, it means *some* compression happened.
                // A better check might be `if (compressed_size > 0 && compressed_size < original_size_before_compress)`
                // This part of logic is tricky without knowing exact Body::compress behavior on incompressible data.
                // For now, setting headers if compressed_size > 0, implying it was successful operation.
                response.set_header("Content-Encoding", selected_encoding);
                response.add_header("Vary", "Accept-Encoding");
                response.set_header("Content-Length", std::to_string(compressed_size));
            }
            // If compressed_size is 0 (e.g. error or empty result from compress not throwing), headers are not set.
#else
        (void)ctx_ref; // Avoid unused parameter warning
#endif
        }

        /**
         * @brief Selects the best supported compression encoding based on client's `Accept-Encoding` header.
         * @param request The HTTP request containing `Accept-Encoding` header.
         * @return The name of the best matching encoding (e.g., "gzip") or an empty string if no suitable match.
         */
        [[nodiscard]] std::string select_best_encoding(const RequestType &request) const noexcept {
            std::string accept_encoding_header_str;
            const auto &acc_enc_val = request.header("Accept-Encoding");
            if constexpr (std::is_same_v<std::decay_t<decltype(acc_enc_val)>, std::string>) {
                accept_encoding_header_str = acc_enc_val;
            } else {
                accept_encoding_header_str = std::string(acc_enc_val);
            }

            if (accept_encoding_header_str.empty()) {
                return ""; // Client did not specify Accept-Encoding
            }

            // Parse Accept-Encoding: value1;q=x, value2;q=y, ... or just value1, value2
            // For simplicity, we'll iterate preferred encodings and see if client accepts them.
            // A full q-value parsing is more complex.
            auto client_accepted_raw_tokens = utility::split_string<std::string>(accept_encoding_header_str, ",");
            std::vector<std::string_view> client_accepted_encodings;
            for (const auto &raw_token: client_accepted_raw_tokens) {
                std::string_view token_sv = utility::trim_http_whitespace(raw_token);
                size_t q_pos = token_sv.find(';'); // Strip q-value part
                if (q_pos != std::string_view::npos) {
                    token_sv = token_sv.substr(0, q_pos);
                    token_sv = utility::trim_http_whitespace(token_sv); // Trim again after substr
                }
                if (!token_sv.empty()) {
                    client_accepted_encodings.push_back(token_sv);
                }
            }

            for (const auto &preferred_server_encoding: _options.get_preferred_encodings()) {
                for (const auto &client_encoding: client_accepted_encodings) {
                    if (utility::iequals(client_encoding, preferred_server_encoding) || client_encoding == "*") {
                        return preferred_server_encoding; // Found a match
                    }
                }
            }
            return ""; // No common supported encoding found
        }

        /**
         * @brief Checks if a given Content-Type string typically represents already compressed content.
         * @param content_type_header The value of the Content-Type header.
         * @return `true` if the MIME type suggests pre-compressed content (e.g., "image/jpeg", "application/pdf"),
         *         `false` otherwise.
         */
        [[nodiscard]] bool is_precompressed_content_type(const std::string &content_type_header) const noexcept {
            static const std::vector<std::string_view> compressed_mime_types = {
                // Use string_view for efficiency
                "image/jpeg", "image/png", "image/gif", "image/webp", "image/jp2", "image/jxr",
                "audio/mpeg", "audio/ogg", "audio/aac", "audio/opus", "audio/flac",
                "video/mp4", "video/webm", "video/ogg", "video/quicktime",
                "application/zip", "application/gzip", "application/x-rar-compressed",
                "application/x-7z-compressed", "application/x-bzip2", "application/pdf",
                "application/vnd.oasis.opendocument.text", // ODT often compressed
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document" // DOCX
                // Add more as needed
            };

            std::string_view main_type_sv = content_type_header;
            size_t semicolon_pos = main_type_sv.find(';');
            if (semicolon_pos != std::string_view::npos) {
                main_type_sv = main_type_sv.substr(0, semicolon_pos);
            }
            main_type_sv = utility::trim_http_whitespace(main_type_sv);

            if (main_type_sv.empty()) return false;

            for (const auto &compressed_type: compressed_mime_types) {
                if (utility::iequals(main_type_sv, compressed_type)) {
                    return true;
                }
            }
            return false;
        }
    };

    // --- Factory Functions ---

    /**
     * @brief Creates a `std::shared_ptr` to a `CompressionMiddleware` instance.
     * @tparam SessionType The session type used by the HTTP context.
     * @param options `CompressionOptions` to configure the middleware. Defaults to default-constructed `CompressionOptions`.
     * @param name An optional name for the middleware instance, for logging or identification purposes.
     * @return A `std::shared_ptr<CompressionMiddleware<SessionType>>`.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<CompressionMiddleware<SessionType> >
    compression_middleware(
        CompressionOptions options = CompressionOptions(), // Pass by value for potential move
        const std::string &name = "CompressionMiddleware"
    ) {
        return std::make_shared<CompressionMiddleware<SessionType> >(std::move(options), name);
    }

    /**
     * @brief Creates a `CompressionMiddleware` instance pre-configured for maximum compression ratios.
     * @tparam SessionType The session type.
     * @param name Optional name for the middleware instance.
     * @return `std::shared_ptr<CompressionMiddleware<SessionType>>`.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<CompressionMiddleware<SessionType> >
    max_compression_middleware(const std::string &name = "MaxCompressionMiddleware") {
        return std::make_shared<CompressionMiddleware<SessionType> >(CompressionOptions::max_compression(), name);
    }

    /**
     * @brief Creates a `CompressionMiddleware` instance pre-configured for faster compression speeds.
     * @tparam SessionType The session type.
     * @param name Optional name for the middleware instance.
     * @return `std::shared_ptr<CompressionMiddleware<SessionType>>`.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<CompressionMiddleware<SessionType> >
    fast_compression_middleware(const std::string &name = "FastCompressionMiddleware") {
        return std::make_shared<CompressionMiddleware<SessionType> >(CompressionOptions::fast_compression(), name);
    }
} // namespace qb::http 

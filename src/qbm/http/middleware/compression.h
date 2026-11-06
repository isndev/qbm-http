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
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <algorithm> // For std::find_if
#include <charconv>  // std::from_chars: a declared Content-Length against min_size_to_compress (Huly QB-1208)
#include <chrono>    // For std::chrono::seconds etc.
#include <cstdint>   // std::uint8_t: the coder's bytes (Huly QB-1208)
#include <memory>    // For std::shared_ptr
#include <stdexcept> // For std::runtime_error (used by Body compression)
#include <string>    // For std::string
#include <string_view>
#include <vector> // For std::vector

#include "../body.h"                    // For qb::http::Body
#include "../routing/response_stream.h" // qb::http::stream_filter: a streamed body coded on the fly (Huly QB-1208)
#include "../request.h"                 // For qb::http::Request (used by Context)
#include "../response.h"                // For qb::http::Response (used by Context)
#include "../routing/middleware.h"      // For IMiddleware, Context, AsyncTaskResult, HookPoint
#include "../types.h"                   // For qb::http::status constants and qb::http::method
#include "../utility.h"                 // For qb::http::utility::split_string, ::iequals

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
    bool                     _compress_responses;   ///< If true, middleware will attempt to compress response bodies.
    bool                     _decompress_requests;  ///< If true, middleware will attempt to decompress request bodies.
    size_t                   _min_size_to_compress; ///< Minimum response body size (bytes) to consider for compression.
    std::vector<std::string> _preferred_encodings;  ///< Ordered list of preferred server-side compression encodings.

public:
    /**
     * @brief Default constructor.
     *
     * Initializes with common defaults:
     * - Response compression: enabled
     * - Request decompression: enabled
     * - Minimum size to compress: 1024 bytes
     * - Preferred encodings: those of {"zstd", "br", "gzip", "deflate"} this build registers, in that order --
     *   {"gzip", "deflate"} unless qb was built with `QB_WITH_ZSTD` / `QB_WITH_BROTLI` (3.3, Huly QB-93)
     */
    CompressionOptions() noexcept;

    /**
     * @brief Enables or disables compression of HTTP response bodies.
     * @param enable If `true`, responses may be compressed. Default is `true`.
     * @return Reference to this `CompressionOptions` instance for chaining.
     */
    CompressionOptions &
    compress_responses(bool enable) noexcept {
        _compress_responses = enable;
        return *this;
    }

    /**
     * @brief Enables or disables decompression of HTTP request bodies.
     * @param enable If `true`, incoming request bodies with `Content-Encoding` may be decompressed. Default is `true`.
     * @return Reference to this `CompressionOptions` instance for chaining.
     */
    CompressionOptions &
    decompress_requests(bool enable) noexcept {
        _decompress_requests = enable;
        return *this;
    }

    /**
     * @brief Sets the minimum size (in bytes) a response body must have to be eligible for compression.
     * Responses smaller than this size will not be compressed, even if other conditions are met.
     * @param size The minimum size in bytes. Default is 1024.
     * @return Reference to this `CompressionOptions` instance for chaining.
     */
    CompressionOptions &
    min_size_to_compress(size_t size) noexcept {
        _min_size_to_compress = size;
        return *this;
    }

    /**
     * @brief Sets the list of preferred compression encodings that the server supports and prefers, in order of preference.
     * Example: `{"gzip", "deflate"}`.
     * This list is used to negotiate with the client's `Accept-Encoding` header: the client's highest q-value wins,
     * this order breaks a tie, and a name this build does not register is passed over (3.3, Huly QB-93).
     * @param encodings A vector of strings representing encoding names (e.g., "gzip").
     * @return Reference to this `CompressionOptions` instance for chaining.
     */
    CompressionOptions &
    preferred_encodings(std::vector<std::string> encodings) {
        // Can allocate
        _preferred_encodings = std::move(encodings);
        return *this;
    }

    /**
     * @brief Provides a pre-configured `CompressionOptions` instance optimized for higher compression ratios.
     * Compresses from 256 bytes and prefers the smallest output: brotli, then gzip and deflate, then zstd (whose
     * factory level trades ratio for speed) -- each only when this build registers it.
     * @return A `CompressionOptions` instance with settings for maximum compression.
     */
    [[nodiscard]] static CompressionOptions max_compression() noexcept;

    /**
     * @brief Provides a pre-configured `CompressionOptions` instance optimized for faster compression speed.
     * Compresses from 2048 bytes and prefers the cheapest encoder: zstd, then deflate and gzip, then brotli (slower
     * than zlib on small bodies) -- each only when this build registers it.
     * @return A `CompressionOptions` instance with settings for fast compression.
     */
    [[nodiscard]] static CompressionOptions fast_compression() noexcept;

    // --- Getters ---
    [[nodiscard]] bool
    should_compress_responses() const noexcept {
        return _compress_responses;
    }
    [[nodiscard]] bool
    should_decompress_requests() const noexcept {
        return _decompress_requests;
    }
    [[nodiscard]] size_t
    get_min_size_to_compress() const noexcept {
        return _min_size_to_compress;
    }

    [[nodiscard]] const std::vector<std::string> &
    get_preferred_encodings() const noexcept {
        return _preferred_encodings;
    }
};

#ifdef QB_HAS_COMPRESSION
namespace detail {
/**
 * @brief A streamed body's content coding (Huly QB-1208): qb-io's incremental compressor, each piece flushed as it
 *        is coded (a partial flush: what a piece produced leaves with it, an event stream's events included), the
 *        stream finished at `end()`. The state is the codec's (zlib: about 384 KiB for its window and its memory
 *        level); the output of a piece is bounded by `bound()`, which the stream admits the piece against before
 *        coding it, so the memory bound of a streamed download (QB-101) holds: the session's high watermark, a
 *        piece, its coded form, and this state.
 */
class StreamCoding final : public stream_filter {
    std::unique_ptr<qb::compression::compress_provider>
        _coder; ///< made at the first piece (a HEAD's stream, or one buffered after all, never pays for it); one that cannot be made fails that
                ///< piece, the exchange aborted
    std::string _name;

    /// Past the first window (the bound of the piece), the rounds of 16 KiB a call that filled its window may add: a
    /// flush's remainder is a few bytes, so a coder still making output here never stops, and is refused.
    static constexpr std::size_t max_rounds = 64;

    /// Hand `piece` to the coder under `hint`, appending what comes out to `out`: a call that filled its window is
    /// repeated for the rest (the provider's contract: the flush may hold more), a last one until the coder says it
    /// is done. A repeated call that takes nothing and makes nothing is a coder that cannot go on; one that ends its
    /// stream with input left did not code this piece; one that never stops making output is cut at `max_rounds`.
    [[nodiscard]] bool
    run(std::string_view piece, std::string &out, qb::compression::operation_hint hint) {
        try {
            if (!_coder) {
                _coder = qb::compression::builtin::make_compressor(_name);
                if (!_coder)
                    return false;
            }
            std::size_t offset = 0;
            std::size_t window = std::max<std::size_t>(bound(piece.size()), 1024);
            std::size_t rounds = 0;
            while (true) {
                const std::size_t before = out.size();
                out.resize(before + window);
                std::size_t taken = 0;
                bool        done  = false;
                const auto  made  = _coder->compress(reinterpret_cast<const std::uint8_t *>(piece.data()) + offset, piece.size() - offset,
                                                     reinterpret_cast<std::uint8_t *>(out.data()) + before, window, hint, taken, done);
                out.resize(before + made);
                offset += taken;
                const bool input_left = offset < piece.size();
                const bool finishing  = hint == qb::compression::operation_hint::is_last && !done;
                if (!input_left && !finishing && made < window)
                    return true;
                if (taken == 0 && made == 0)
                    return false; // no progress: a coder that cannot go on never loops here
                if (done && input_left)
                    return false; // the stream ended with input left: not a coding of this piece
                if (++rounds > max_rounds)
                    return false; // a coder that never stops making output
                window = 16 * 1024;
            }
        } catch (const std::exception &) {
            return false;
        }
    }

public:
    /// The coding `name` names -- gzip, deflate, zstd or br, whichever this build registers -- its coder made at the
    /// first piece.
    explicit StreamCoding(std::string name)
        : _name(std::move(name)) {}
    /// A coder of the caller's: the tests' scripted providers, the benchmark's.
    StreamCoding(std::unique_ptr<qb::compression::compress_provider> coder, std::string name)
        : _coder(std::move(coder))
        , _name(std::move(name)) {}
    [[nodiscard]] std::string_view
    name() const noexcept override {
        return _name;
    }
    /// A piece never grows past it under any of the four codecs -- deflate's own bound (stored blocks and a flush's
    /// few bytes), zstd's `ZSTD_COMPRESSBOUND`, brotli's flush -- for the pieces a stream writes, rounded up; for 0 it
    /// is the tail's room `finish()` keeps.
    [[nodiscard]] std::size_t
    bound(std::size_t piece) const noexcept override {
        return piece + (piece >> 8) + 128;
    }
    [[nodiscard]] bool
    code(std::string_view piece, std::string &out) override {
        return run(piece, out, qb::compression::operation_hint::has_more);
    }
    [[nodiscard]] bool
    finish(std::string &out) override {
        return run({}, out, qb::compression::operation_hint::is_last);
    }
};
} // namespace detail
#endif // QB_HAS_COMPRESSION

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
template <typename SessionType>
class CompressionMiddleware final : public IMiddleware<SessionType> {
public:
    using ContextPtr   = std::shared_ptr<Context<SessionType>>;
    using RequestType  = Request;  // Usually qb::http::Request
    using ResponseType = Response; // Usually qb::http::Response

    /**
     * @brief Constructs `CompressionMiddleware` with default `CompressionOptions`.
     * @param name An optional name for this middleware instance, for logging or identification.
     */
    explicit CompressionMiddleware(std::string name = "CompressionMiddleware") noexcept
        : _options() // Default constructed CompressionOptions
        , _name(std::move(name)) {}

    /**
     * @brief Constructs `CompressionMiddleware` with specified `CompressionOptions`.
     * @param options The compression options to use.
     * @param name An optional name for this middleware instance.
     */
    CompressionMiddleware(CompressionOptions options,
                          std::string        name = "CompressionMiddleware") noexcept
        : _options(std::move(options)) // Options passed by value and moved
        , _name(std::move(name)) {}

    /**
     * @brief Processes the request: attempts to decompress request body if applicable,
     *        and registers a lifecycle hook to compress the response body before sending.
     * @param ctx The shared `Context` for the current request.
     */
    void
    process(ContextPtr ctx) override {
#ifdef QB_HAS_COMPRESSION
        if (_options.should_decompress_requests() && can_decompress_request(ctx->request())) {
            try {
                decompress_request_body(ctx->request());
            } catch (const std::runtime_error &e) {
                ctx->response().status() = qb::http::status::BAD_REQUEST;
                ctx->response().body()   = std::string("Invalid compressed request body: ") + e.what();
                ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                ctx->complete(AsyncTaskResult::COMPLETE); // Stop processing
                return;
            } catch (const std::exception &e) {
                // Catch other potential exceptions from Body::uncompress
                ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                ctx->response().body()   = std::string("Error during request body decompression: ") + e.what();
                ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                ctx->complete(AsyncTaskResult::COMPLETE);
                return;
            }
        }

        if (_options.should_compress_responses()) {
            // Add a PRE_RESPONSE_SEND hook for response compression.
            // This ensures compression happens after all handlers have finalized the response body.
            auto options_snapshot = _options;
            ctx->add_lifecycle_hook([options_snapshot = std::move(options_snapshot)](Context<SessionType> &ctx_ref, HookPoint point) {
                if (point == HookPoint::PRE_RESPONSE_SEND) {
                    if (!ctx_ref.response().body().empty()) {
                        try {
                            compress_response_body(ctx_ref, options_snapshot);
                        } catch (const std::runtime_error &) {
                            // Log error, but don't modify response further at this critical stage.
                            // Or, strip Content-Encoding if partially set before error?
                            // For now, just log (if logging is available).
                            // std::cerr << "CompressionMiddleware: Error compressing response: " << e.what() << std::endl;
                        } catch (const std::exception &) {
                            // std::cerr << "CompressionMiddleware: Generic error compressing response: " << e.what() << std::endl;
                        }
                    } else if (ctx_ref.stream_beginning()) {
                        // The body will come through a stream (Huly QB-86): coded on the fly, piece by piece (Huly QB-1208).
                        try {
                            code_streamed_response(ctx_ref, options_snapshot);
                        } catch (const std::exception &) {
                            // the filter could not be allocated: the stream leaves as it is, its head untouched
                        }
                    }
                }
            });
        }
#endif                                            // QB_HAS_COMPRESSION
        ctx->complete(AsyncTaskResult::CONTINUE); // Continue to next middleware/handler
    }

    /** @brief Gets the name of this middleware instance. */
    [[nodiscard]] std::string
    name() const noexcept override {
        return _name;
    }

    /** @brief Handles cancellation; currently a no-op for this middleware. */
    void
    cancel() noexcept override {
        // No specific asynchronous operations to cancel within this middleware itself.
    }

    /**
     * @brief Updates the compression options for this middleware instance.
     * @param opts The new `CompressionOptions` to use.
     */
    void
    update_options(CompressionOptions opts) noexcept {
        // Pass by value for potential move
        _options = std::move(opts);
    }

    /** @brief Gets a constant reference to the current `CompressionOptions`. */
    [[nodiscard]] const CompressionOptions &
    get_options() const noexcept {
        return _options;
    }

private:
    CompressionOptions _options;
    std::string        _name;

    /**
     * @brief Checks if the request has a `Content-Encoding` header indicating a compressed body.
     * @param request The HTTP request object.
     * @return `true` if `Content-Encoding` header is present and not empty, `false` otherwise.
     */
    [[nodiscard]] bool
    can_decompress_request(const RequestType &request) const noexcept {
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
    void
    decompress_request_body(RequestType &request) {
#ifdef QB_HAS_COMPRESSION
        // `request.header()` returns `const std::string&`; borrow it for `Body::uncompress`.
        const std::string &encoding_str = request.header("Content-Encoding");

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
        (void) request; // Avoid unused parameter warning
#endif
    }

    /**
     * @brief Compresses the response body in-place if `QB_HAS_COMPRESSION` is defined and conditions are met.
     * Modifies the response object by replacing its body with compressed content and setting
     * `Content-Encoding`, `Vary`, and `Content-Length` headers.
     * @param ctx_ref Reference to the `Context` object containing the response.
     * @throws std::runtime_error if compression fails (e.g., unsupported encoding within Body::compress).
     */
    static void
    compress_response_body(Context<SessionType> &ctx_ref, const CompressionOptions &options) {
#ifdef QB_HAS_COMPRESSION
        ResponseType &response = ctx_ref.response(); // Get mutable reference

        if (response.body().size() < options.get_min_size_to_compress() || response.has_header("Content-Encoding")
            || is_precompressed_content_type(std::string(response.content_type().type()))) {
            // Use parsed ContentType
            return;
        }
        if (response.status() == qb::http::status::PARTIAL_CONTENT || response.has_header("Content-Range"))
            return; // a range is never coded, read whole or streamed: a Content-Range names identity octets (Huly QB-1208)

        std::string selected_encoding = select_best_encoding(ctx_ref.request(), options);
        if (selected_encoding.empty()) {
            return; // No suitable encoding accepted by client or supported by server
        }

        // Redundant check, already done above, but kept for safety.
        if (response.body().size() < options.get_min_size_to_compress()) {
            return;
        }

        const std::size_t original_size = response.body().size();
        const std::string original_body = response.body().as<std::string>();

        // Body::compress can throw std::runtime_error
        std::size_t compressed_size = response.body().compress(selected_encoding);

        if (compressed_size > 0 && compressed_size < original_size) {
            // Only set headers if compression was effective
            response.set_header("Content-Encoding", selected_encoding);
            if (!vary_lists_accept_encoding(response))
                response.add_header("Vary", "Accept-Encoding");
            response.set_header("Content-Length", std::to_string(compressed_size));
            // The coded representation is not byte-equal, and a client that resumed it under a Range without If-Range
            // would splice identity octets into it: a strong ETag turns weak, Accept-Ranges goes (as on a stream,
            // Huly QB-1208).
            if (response.has_header("ETag")) {
                const std::string &tag = response.header("ETag");
                if (tag.size() < 2 || tag[0] != 'W' || tag[1] != '/')
                    response.set_header("ETag", "W/" + tag);
            }
            response.remove_header("Accept-Ranges");
        } else if (compressed_size > 0) {
            response.body() = original_body;
            response.remove_header("Content-Encoding");
            response.remove_header("Content-Length");
        }
        // If compressed_size is 0 (e.g. error or empty result from compress not throwing), headers are not set.
#else
        (void) ctx_ref; // Avoid unused parameter warning
#endif
    }

    /// Whether a `Vary` value of `response` lists `Accept-Encoding` already (or `*`): a second line is never added.
    [[nodiscard]] static bool
    vary_lists_accept_encoding(ResponseType const &response) {
        const auto it = response.headers().find("Vary");
        if (it == response.headers().end())
            return false;
        for (const std::string &line : it->second)
            if (utility::list_names(line, "Accept-Encoding"))
                return true;
        return false;
    }

#ifdef QB_HAS_COMPRESSION
    /**
     * @brief Hand the stream `begin_stream()` is creating a content coding (Huly QB-1208), when the client accepts one
     *        the build registers, the type is compressible, the status is not 206 and no coding is on the head
     *        already; a declared length under `min_size_to_compress` is left as it is, a length unknown taken as
     *        large. The head is the context's to set, once the hooks ran and the framing is known: `Content-Length`
     *        dropped (chunked on HTTP/1.1, END_STREAM or FIN on HTTP/2 and HTTP/3), `Content-Encoding`,
     *        `Accept-Encoding` listed in `Vary` once, a strong `ETag` made weak, `Accept-Ranges` dropped; an HTTP/1.0
     *        request, which reads no chunked body, keeps its length and gets no coding, as does a head a later hook
     *        made a range or coded itself. The coder itself is made at the first piece: a HEAD's stream, or one
     *        buffered after all, never allocates it.
     */
    static void
    code_streamed_response(Context<SessionType> &ctx_ref, const CompressionOptions &options) {
        ResponseType &response = ctx_ref.response();
        if (response.status() == qb::http::status::PARTIAL_CONTENT || response.has_header("Content-Range")
            || response.has_header("Content-Encoding") || is_precompressed_content_type(std::string(response.content_type().type())))
            return; // a range is never coded; a coding already there is the handler's
        if (response.has_header("Content-Length")) {
            const std::string &length   = response.header("Content-Length");
            std::uint64_t      declared = 0;
            const auto [end, ec]        = std::from_chars(length.data(), length.data() + length.size(), declared);
            if (ec == std::errc{} && end == length.data() + length.size() && declared < options.get_min_size_to_compress())
                return;
        }
        const std::string encoding = select_best_encoding(ctx_ref.request(), options);
        if (encoding.empty())
            return;
        ctx_ref.set_stream_coding(std::make_unique<detail::StreamCoding>(encoding)); // the coder is made at the first piece
    }
#endif // QB_HAS_COMPRESSION

    /**
     * @brief Selects the best supported compression encoding based on client's `Accept-Encoding` header.
     * @param request The HTTP request containing `Accept-Encoding` header.
     * @return The name of the best matching encoding (e.g., "gzip") or an empty string if no suitable match.
     */
    [[nodiscard]] static std::string
    select_best_encoding(const RequestType &request, const CompressionOptions &options) noexcept {
        const std::string &accept_encoding_header_str = request.header("Accept-Encoding");

        if (accept_encoding_header_str.empty()) {
            return ""; // Client did not specify Accept-Encoding
        }

        // Parse `Accept-Encoding: value1;q=x, value2;q=y, ...` over
        // string_views and honour q=0 exclusions. When several supported
        // encodings are acceptable, pick the highest client q-value and use
        // the server preference list as a deterministic tie-breaker.
        struct AcceptedEncoding {
            std::string_view name;
            int              q_milli = 1000;
        };

        auto parse_q_value_milli = [](std::string_view raw_q) noexcept -> int {
            auto q = utility::trim_http_whitespace(raw_q);
            if (q.empty()) {
                return -1;
            }
            if (q == "1" || q == "1.0" || q == "1.00" || q == "1.000") {
                return 1000;
            }
            if (q[0] != '0') {
                return -1;
            }
            if (q.size() == 1) {
                return 0;
            }
            if (q.size() < 3 || q[1] != '.') {
                return -1;
            }

            int milli = 0;
            int place = 100;
            for (std::size_t i = 2; i < q.size(); ++i) {
                const char c = q[i];
                if (c < '0' || c > '9' || place == 0) {
                    return -1;
                }
                milli += (c - '0') * place;
                place /= 10;
            }
            return milli;
        };

        auto parse_q_value = [parse_q_value_milli](std::string_view token) noexcept -> int {
            auto params = utility::split_string<std::string_view>(token, ";");
            for (std::size_t i = 1; i < params.size(); ++i) {
                auto       param  = utility::trim_http_whitespace(params[i]);
                const auto eq_pos = param.find('=');
                if (eq_pos == std::string_view::npos)
                    continue;
                auto key = utility::trim_http_whitespace(param.substr(0, eq_pos));
                if (!utility::iequals(key, "q"))
                    continue;

                auto      value   = utility::trim_http_whitespace(param.substr(eq_pos + 1));
                const int q_milli = parse_q_value_milli(value);
                return q_milli >= 0 ? q_milli : 0;
            }
            return 1000;
        };

        std::vector<AcceptedEncoding> accepted_encodings;
        auto                          client_tokens = utility::split_string<std::string_view>(accept_encoding_header_str, ",");
        for (auto &token : client_tokens) {
            const auto q    = parse_q_value(token);
            auto       name = utility::trim_http_whitespace(token);
            if (const auto q_pos = name.find(';'); q_pos != std::string_view::npos) {
                name = utility::trim_http_whitespace(name.substr(0, q_pos));
            }
            if (!name.empty()) {
                accepted_encodings.push_back({name, q});
            }
        }

        std::string best_encoding;
        int         best_q = 0;
        for (const auto &preferred_server_encoding : options.get_preferred_encodings()) {
#if defined(QB_HAS_COMPRESSION)
            // A codec this build does not register cannot be produced: choosing it made Body::compress throw and the
            // response go out uncompressed, though another accepted codec was at hand (Huly QB-93).
            if (!qb::compression::builtin::algorithm::supported(preferred_server_encoding))
                continue;
#endif
            int explicit_q = -1;
            int wildcard_q = -1;

            for (const auto &client_encoding : accepted_encodings) {
                if (utility::iequals(client_encoding.name, preferred_server_encoding)) {
                    explicit_q = client_encoding.q_milli;
                    break;
                }
                if (client_encoding.name == "*") {
                    wildcard_q = client_encoding.q_milli;
                }
            }

            const int candidate_q = explicit_q >= 0 ? explicit_q : wildcard_q;
            if (candidate_q > best_q) {
                best_q        = candidate_q;
                best_encoding = preferred_server_encoding;
            }
        }
        return best_q > 0 ? best_encoding : "";
    }

    /**
     * @brief Checks if a given Content-Type string typically represents already compressed content.
     * @param content_type_header The value of the Content-Type header.
     * @return `true` if the MIME type suggests pre-compressed content (e.g., "image/jpeg", "application/pdf"),
     *         `false` otherwise.
     */
    [[nodiscard]] static bool
    is_precompressed_content_type(const std::string &content_type_header) noexcept {
        static const std::vector<std::string_view> compressed_mime_types = {
            // Use string_view for efficiency
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
            "image/jp2",
            "image/jxr",
            "audio/mpeg",
            "audio/ogg",
            "audio/aac",
            "audio/opus",
            "audio/flac",
            "video/mp4",
            "video/webm",
            "video/ogg",
            "video/quicktime",
            "application/zip",
            "application/gzip",
            "application/x-rar-compressed",
            "application/x-7z-compressed",
            "application/x-bzip2",
            "application/pdf",
            "application/vnd.oasis.opendocument.text",                                // ODT often compressed
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document" // DOCX
            // Add more as needed
        };

        std::string_view main_type_sv  = content_type_header;
        size_t           semicolon_pos = main_type_sv.find(';');
        if (semicolon_pos != std::string_view::npos) {
            main_type_sv = main_type_sv.substr(0, semicolon_pos);
        }
        main_type_sv = utility::trim_http_whitespace(main_type_sv);

        if (main_type_sv.empty())
            return false;

        for (const auto &compressed_type : compressed_mime_types) {
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
template <typename SessionType>
[[nodiscard]] std::shared_ptr<CompressionMiddleware<SessionType>>
compression_middleware(CompressionOptions options = CompressionOptions(), // Pass by value for potential move
                       const std::string &name    = "CompressionMiddleware") {
    return std::make_shared<CompressionMiddleware<SessionType>>(std::move(options), name);
}

/**
 * @brief Creates a `CompressionMiddleware` instance pre-configured for maximum compression ratios.
 * @tparam SessionType The session type.
 * @param name Optional name for the middleware instance.
 * @return `std::shared_ptr<CompressionMiddleware<SessionType>>`.
 */
template <typename SessionType>
[[nodiscard]] std::shared_ptr<CompressionMiddleware<SessionType>>
max_compression_middleware(const std::string &name = "MaxCompressionMiddleware") {
    return std::make_shared<CompressionMiddleware<SessionType>>(CompressionOptions::max_compression(), name);
}

/**
 * @brief Creates a `CompressionMiddleware` instance pre-configured for faster compression speeds.
 * @tparam SessionType The session type.
 * @param name Optional name for the middleware instance.
 * @return `std::shared_ptr<CompressionMiddleware<SessionType>>`.
 */
template <typename SessionType>
[[nodiscard]] std::shared_ptr<CompressionMiddleware<SessionType>>
fast_compression_middleware(const std::string &name = "FastCompressionMiddleware") {
    return std::make_shared<CompressionMiddleware<SessionType>>(CompressionOptions::fast_compression(), name);
}
} // namespace qb::http

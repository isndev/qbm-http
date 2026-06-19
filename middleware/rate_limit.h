/**
 * @file qbm/http/middleware/rate_limit.h
 * @brief Defines middleware for HTTP request rate limiting.
 *
 * This file provides the `RateLimitMiddleware` class template and its configuration
 * class `RateLimitOptions`. This middleware tracks the number of requests from client
 * identifiers (e.g., IP address) within a defined time window and rejects requests
 * that exceed a configured maximum, responding with a customizable status code and message.
 * It also adds standard `X-RateLimit-*` headers to responses.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Middleware
 *
 * @note Threading model:
 * Each qb listener / VirtualCore is strictly mono-thread; HTTP sessions
 * registered on a given listener are never accessed concurrently. The
 * `RateLimitMiddleware` therefore stores its client map without any
 * locking.  If the same middleware instance is shared across multiple
 * listeners (e.g. a multi-core server), each listener must own its own
 * instance &mdash; use the `make_rate_limit_middleware` factory per
 * `io_handler` rather than as a static singleton.
 */
#pragma once

#include <chrono>     // For std::chrono::duration, minutes, milliseconds, steady_clock
#include <functional> // For std::function
#include <memory>     // For std::shared_ptr, std::make_shared
#include <string>     // For std::string, std::to_string
#include <typeindex>  // For std::type_index (type-safe client-id extractor)
#include <utility>    // For std::move
#include <vector>     // For std::vector (used in RateLimitOptions setters indirectly)

#include <qb/system/container/unordered_map.h> // For qb::unordered_map

#include "../request.h"            // For qb::http::Request (used by Context)
#include "../response.h"           // For qb::http::Response (used by Context)
#include "../routing/middleware.h" // For IMiddleware, Context, AsyncTaskResult
#include "../types.h"              // For qb::http::status enum

// Security limits for rate limiting to prevent memory exhaustion
namespace qb::http::rate_limit_security {
/** @brief Maximum number of unique clients to track (prevents memory DoS) */
constexpr std::size_t MAX_TRACKED_CLIENTS = 100000;

/** @brief Maximum client ID string length (prevents memory DoS) */
constexpr std::size_t MAX_CLIENT_ID_LENGTH = 256;

/** @brief Default interval at which the opportunistic stale-entry sweep fires. */
constexpr qb::duration STALE_ENTRY_CLEANUP_INTERVAL = std::chrono::minutes{1};

/** @brief Fraction (numerator / denominator) of `MAX_TRACKED_CLIENTS` above which an
 *         emergency sweep is triggered on every incoming request. */
constexpr std::size_t MEMORY_PRESSURE_NUMERATOR   = 9;
constexpr std::size_t MEMORY_PRESSURE_DENOMINATOR = 10;
} // namespace qb::http::rate_limit_security

namespace qb::http {
/**
 * @brief Configuration options for the `RateLimitMiddleware`.
 *
 * Allows specification of the maximum number of requests allowed per time window,
 * the HTTP status code and message for rate-limited responses, and a customizable
 * function to extract client identifiers from requests.
 */
class RateLimitOptions {
public:
    /**
     * @brief Default constructor.
     *
     * Initializes with default rate limiting parameters:
     * - Max requests: 100
     * - Time window: 1 minute
     * - Status code on limit: 429 Too Many Requests
     * - Message on limit: "Rate limit exceeded. Please try again later."
     * Client ID extraction defaults to using X-Forwarded-For or a session placeholder.
     */
    RateLimitOptions() noexcept
        : _max_requests(100)
        , _window(std::chrono::minutes(1))
        , _status_code(qb::http::status::TOO_MANY_REQUESTS)
        , _message("Rate limit exceeded. Please try again later.") {}

    /**
     * @brief Sets the maximum number of requests allowed from a single client within the defined time window.
     * @param max_requests_val The maximum number of requests.
     * @return Reference to this `RateLimitOptions` instance for chaining.
     */
    RateLimitOptions &
    max_requests(size_t max_requests_val) noexcept {
        _max_requests = max_requests_val;
        return *this;
    }

    /**
     * @brief Sets the duration of the time window for rate limiting.
     * @tparam DurationRep The representation type of the duration (e.g., `long long`).
     * @tparam DurationPeriod The period of the duration (e.g., `std::milli`, `std::ratio<1>`).
     * @param window_val The duration of the time window (e.g., `std::chrono::seconds(60)`).
     * @return Reference to this `RateLimitOptions` instance for chaining.
     */
    RateLimitOptions &
    window(qb::duration window_val) noexcept {
        _window = window_val;
        return *this;
    }

    /**
     * @brief Sets the HTTP status code to be returned when a request is rate-limited.
     * @param status_code_val The `qb::http::status` enum value. Default is `qb::http::status::TOO_MANY_REQUESTS` (429).
     * @return Reference to this `RateLimitOptions` instance for chaining.
     */
    RateLimitOptions &
    status_code(qb::http::status status_code_val) noexcept {
        _status_code = status_code_val;
        return *this;
    }

    /**
     * @brief Sets the custom message for the response body when a request is rate-limited.
     * @param msg The message string. Passed by value for potential move.
     * @return Reference to this `RateLimitOptions` instance for chaining.
     */
    RateLimitOptions &
    message(std::string msg) {
        // std::string assignment can allocate
        _message = std::move(msg);
        return *this;
    }

    /**
     * @brief Sets a custom function to extract a client identifier string from the request context.
     * This identifier is used as the key for tracking request counts.
     * If not set, a default extractor attempts to use "X-Forwarded-For" header or a session-based ID.
     * @tparam SessionType The session type of the `Context` that the extractor function will receive.
     * @param extractor A function with signature `std::string(const Context<SessionType>&)`.
     * @return Reference to this `RateLimitOptions` instance for chaining.
     */
    template <typename SessionType>
    RateLimitOptions &
    client_id_extractor(std::function<std::string(const Context<SessionType> &)> extractor) {
        // std::function assignment can allocate
        _client_id_extractor_type = std::type_index(typeid(SessionType));
        _client_id_extractor_fn   = [extractor_cb = std::move(extractor)](const void *ctx_ptr) -> std::string {
            // Safe: extract_client_id verifies SessionType matches the
            // type recorded above before invoking this, so ctx_ptr is
            // always a Context<SessionType>.
            const auto *typed_ctx = static_cast<const Context<SessionType> *>(ctx_ptr);
            return extractor_cb(*typed_ctx);
        };
        return *this;
    }

    /**
     * @brief Provides a pre-configured `RateLimitOptions` instance with permissive settings.
     * Suitable for development or internal services where rate limiting is less strict.
     * Defaults: 1000 requests per minute.
     * @return A `RateLimitOptions` instance with permissive settings.
     */
    [[nodiscard]] static RateLimitOptions
    permissive() noexcept {
        return RateLimitOptions()
            .max_requests(1000) // Higher limit
            .window(std::chrono::minutes(1))
            .message("You have reached the rate limit. Please try again later.");
    }

    /**
     * @brief Provides a pre-configured `RateLimitOptions` instance with more restrictive, secure defaults.
     * Suitable as a baseline for production environments.
     * Defaults: 60 requests per minute.
     * @return A `RateLimitOptions` instance with secure settings.
     */
    [[nodiscard]] static RateLimitOptions
    secure() noexcept {
        return RateLimitOptions()
            .max_requests(60) // Stricter limit
            .window(std::chrono::minutes(1))
            .message("Rate limit exceeded. Please try again later.");
    }

    // --- Getters ---
    [[nodiscard]] size_t
    get_max_requests() const noexcept {
        return _max_requests;
    }
    [[nodiscard]] qb::duration
    get_window() const noexcept {
        return _window;
    }
    [[nodiscard]] qb::http::status
    get_status_code() const noexcept {
        return _status_code;
    }
    [[nodiscard]] const std::string &
    get_message() const noexcept {
        return _message;
    }

    [[nodiscard]] bool
    has_custom_client_id_extractor() const noexcept {
        return static_cast<bool>(_client_id_extractor_fn);
    }

    /**
     * @brief Extracts a client identifier string from the provided request context.
     *
     * If a custom extractor function was set via `client_id_extractor()`, it is used.
     * Otherwise, this method attempts to use the value of the "X-Forwarded-For" HTTP header
     * (taking the first IP if it's a list). If that header is not present or empty, and a session
     * exists in the context, a placeholder session identifier is generated.
     * As a final fallback, it returns "unknown_client".
     *
     * @tparam SessionType The session type of the `Context`.
     * @param ctx The request `Context` from which to extract the client identifier.
     * @return A string representing the client identifier.
     * @note This method is not strictly `noexcept` due to potential string operations (e.g., from header access or `std::to_string`).
     */
    template <typename SessionType>
    [[nodiscard]] std::string
    extract_client_id(const Context<SessionType> &ctx) const {
        // Only invoke the type-erased extractor when the Context type matches
        // the SessionType it was configured with; otherwise the static_cast
        // inside it would be undefined behaviour. On mismatch, fall through to
        // the built-in extractor.
        if (_client_id_extractor_fn && _client_id_extractor_type == std::type_index(typeid(SessionType))) {
            try {
                return _client_id_extractor_fn(static_cast<const void *>(&ctx));
            } catch (const std::bad_function_call & /*e*/) {
                // Fallthrough to default if custom extractor fails (e.g. null after move)
            } catch (...) {
                // Fall through to the built-in extractor to keep middleware resilient.
            }
        }

        // Default extraction logic - SECURITY FIX: Improved X-Forwarded-For handling
        std::string client_id_str;

        // SECURITY FIX: Prefer more secure headers over X-Forwarded-For when available
        // Order of preference (most secure to least):
        // 1. CF-Connecting-IP (Cloudflare) - set by trusted proxy
        // 2. True-Client-IP (Akamai) - set by trusted proxy
        // 3. X-Forwarded-For - can be forged, take rightmost IP
        const auto &cf_header          = ctx.request().header("CF-Connecting-IP");
        const auto &true_client_header = ctx.request().header("True-Client-IP");
        const auto &xff_header         = ctx.request().header("X-Forwarded-For");

        std::string_view header_val_obj;

        if (!cf_header.empty()) {
            header_val_obj = cf_header;
        } else if (!true_client_header.empty()) {
            header_val_obj = true_client_header;
        } else if (!xff_header.empty()) {
            header_val_obj = xff_header;
        }

        if (!header_val_obj.empty()) {
            if constexpr (std::is_convertible_v<decltype(header_val_obj), std::string>) {
                client_id_str = header_val_obj;
            } else if constexpr (std::is_convertible_v<decltype(header_val_obj), std::string_view>) {
                client_id_str = std::string(header_val_obj);
            } else {
                // Fallback for custom String types
                client_id_str.assign(header_val_obj.data(), header_val_obj.length());
            }
        }

        // SECURITY FIX: For X-Forwarded-For, use the RIGHTMOST IP (closest to server)
        // This is less spoofable than the leftmost IP which is client-controlled
        // Note: CF-Connecting-IP and True-Client-IP are already single IPs set by trusted proxies
        if (!client_id_str.empty() && xff_header.empty() == false && header_val_obj.data() == xff_header.data()) {
            // We got the value from X-Forwarded-For, extract rightmost IP
            size_t last_comma = client_id_str.rfind(',');
            if (last_comma != std::string::npos) {
                // Take the last IP and trim whitespace
                client_id_str = client_id_str.substr(last_comma + 1);
                // Trim leading whitespace
                size_t start = client_id_str.find_first_not_of(" \t");
                if (start != std::string::npos) {
                    client_id_str = client_id_str.substr(start);
                }
            }
        }

        if (!client_id_str.empty()) {
            return client_id_str;
        }

        if (ctx.session()) {
            // Requires Context::session() to return a type convertible to bool or a smart pointer
            // Using reinterpret_cast for a unique ID from pointer address. This is a placeholder for a real session ID.
            return "session_placeholder_id:" + std::to_string(reinterpret_cast<uintptr_t>(ctx.session().get()));
        }
        return "unknown_client"; // Fallback identifier
    }

private:
    size_t                                   _max_requests;
    qb::duration                             _window;
    qb::http::status                         _status_code;
    std::string                              _message;
    std::function<std::string(const void *)> _client_id_extractor_fn;                 // Type-erased client ID extractor
    std::type_index                          _client_id_extractor_type{typeid(void)}; // SessionType the extractor was configured for
};

/**
 * @brief Middleware to limit the rate of HTTP requests from clients based on a configured policy.
 *
 * This middleware tracks the number of requests associated with a client identifier (e.g., IP address,
 * user ID) within a defined time window. If a client exceeds the maximum allowed requests for that
 * window, subsequent requests are rejected with a specific HTTP status code (e.g., 429 Too Many Requests)
 * and a custom message. It also adds standard rate limit headers (`X-RateLimit-Limit`,
 * `X-RateLimit-Remaining`, `X-RateLimit-Reset`) to all responses for clients being tracked.
 *
 * @note The middleware is lock-free: it relies on the qb mono-thread
 * per-listener guarantee. If the same instance is used from multiple
 * listeners, instantiate one per listener (see the factory helper at
 * the bottom of this file).
 *
 * @tparam SessionType The type of the session object managed by the router, used by `Context`.
 */
template <typename SessionType>
class RateLimitMiddleware final : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;

    /**
     * @brief Constructs `RateLimitMiddleware` with default `RateLimitOptions`.
     * @param name An optional name for this middleware instance (for logging/debugging).
     */
    explicit RateLimitMiddleware(std::string name = "RateLimitMiddleware") noexcept
        : _options(std::make_shared<RateLimitOptions>())
        , // Uses default RateLimitOptions
        _name(std::move(name)) {}

    /**
     * @brief Constructs `RateLimitMiddleware` with specified `RateLimitOptions`.
     * @param options The rate limiting configuration. Passed by value and moved.
     * @param name An optional name for this middleware instance.
     */
    explicit RateLimitMiddleware(
        RateLimitOptions options,
        std::string      name = "RateLimitMiddleware") noexcept // Assuming make_shared and RateLimitOptions move ctor are noexcept
        : _options(std::make_shared<RateLimitOptions>(std::move(options)))
        , _name(std::move(name)) {}

    /**
     * @brief Processes the incoming request, applying rate limiting logic.
     *
     * Extracts a client ID, checks if the request count for this ID exceeds the configured limit
     * within the time window. If rate-limited, sends an error response. Otherwise, increments
     * the count and allows the request to proceed. Sets `X-RateLimit-*` headers on the response.
     * @param ctx The shared `Context` for the current request.
     */
    void
    process(ContextPtr ctx) override {
        // Security: Validate client ID length to prevent memory DoS
        const std::string client_id_raw = _options->extract_client_id(*ctx);
        if (client_id_raw.length() > rate_limit_security::MAX_CLIENT_ID_LENGTH) {
            // Reject requests with excessively long client IDs
            ctx->response().status() = qb::http::status::BAD_REQUEST;
            ctx->response().body()   = "Invalid client identifier";
            ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
            ctx->complete(AsyncTaskResult::COMPLETE);
            return;
        }

        // Use truncated client ID for tracking if needed
        const std::string client_id = client_id_raw.substr(0, rate_limit_security::MAX_CLIENT_ID_LENGTH);

        const auto now = std::chrono::steady_clock::now();

        // Opportunistic housekeeping.
        //
        // The `_client_data` map is append-only in the happy path: every
        // unseen client adds an entry that never gets removed unless the
        // admin calls `reset_client`/`reset_all_clients`. On a long-running
        // server facing a scan, this grows until it hits
        // `MAX_TRACKED_CLIENTS`, at which point genuine new clients get
        // shut out with 503. To prevent that, we evict entries whose
        // window has elapsed (i.e. the client has been silent for at
        // least one full window) either:
        //
        //   * periodically, throttled by STALE_ENTRY_CLEANUP_INTERVAL, so
        //     the O(N) sweep is at most once per minute by default;
        //   * eagerly, whenever the map crosses the memory-pressure
        //     threshold (90 % of the cap by default), regardless of the
        //     throttle &mdash; this is what actually recovers capacity
        //     before the hard cap starts refusing clients.
        const bool periodic_due    = (now >= _next_cleanup_time);
        const bool memory_pressure = _client_data.size() * rate_limit_security::MEMORY_PRESSURE_DENOMINATOR
                                     >= rate_limit_security::MAX_TRACKED_CLIENTS * rate_limit_security::MEMORY_PRESSURE_NUMERATOR;
        if (periodic_due || memory_pressure) {
            evict_stale_entries_internal(now);
            _next_cleanup_time = now + rate_limit_security::STALE_ENTRY_CLEANUP_INTERVAL;
        }

        bool       rate_limited_flag    = false;
        bool       memory_limit_reached = false;
        ClientData client_data_for_headers; // Snapshot used to build rate-limit headers.

        // qb sessions on a given listener are mono-thread, so no locking
        // is required to access `_client_data`. See the note on the
        // class doc for multi-listener topologies.
        if (_client_data.size() >= rate_limit_security::MAX_TRACKED_CLIENTS && _client_data.find(client_id) == _client_data.end()) {
            memory_limit_reached = true;
        } else {
            ClientData &current_client_record = _client_data[client_id]; // Creates if not exist

            // Check if the window has reset for this client
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - current_client_record.last_reset_time) >= _options->get_window()) {
                current_client_record.request_count   = 0;
                current_client_record.last_reset_time = now;
            }

            if (current_client_record.request_count >= _options->get_max_requests()) {
                rate_limited_flag = true;
            } else {
                current_client_record.request_count++;
            }
            client_data_for_headers = current_client_record;
        }

        // Handle memory limit reached
        if (memory_limit_reached) {
            ctx->response().status() = qb::http::status::SERVICE_UNAVAILABLE;
            ctx->response().body()   = "Server capacity exceeded";
            ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
            ctx->complete(AsyncTaskResult::COMPLETE);
            return;
        }

        add_rate_limit_headers(ctx->response(), client_data_for_headers);

        if (rate_limited_flag) {
            ctx->response().status() = _options->get_status_code();
            ctx->response().body()   = _options->get_message(); // Assumes message is plain text or Body handles type
            ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
            // Example, adjust if message is e.g. JSON
            ctx->complete(AsyncTaskResult::COMPLETE); // Stop processing
        } else {
            ctx->complete(AsyncTaskResult::CONTINUE); // Proceed to next middleware/handler
        }
    }

    /** @brief Gets the configured name of this middleware instance. */
    [[nodiscard]] std::string
    name() const noexcept override {
        return _name;
    }

    /** @brief Handles cancellation; currently a no-op for this middleware. */
    void
    cancel() noexcept override {
        // No specific asynchronous operations to cancel.
    }

    /**
     * @brief Resets rate limiting data for all tracked clients.
     * This clears all client request counts and effectively starts fresh windows for everyone.
     * @return Reference to this `RateLimitMiddleware` for chaining.
     */
    RateLimitMiddleware &
    reset_all_clients() noexcept {
        _client_data.clear();
        return *this;
    }

    /**
     * @brief Resets rate limiting data for a specific client identifier.
     * @param client_id The identifier of the client whose rate limit data should be reset.
     * @return Reference to this `RateLimitMiddleware` for chaining.
     */
    RateLimitMiddleware &
    reset_client(const std::string &client_id) {
        _client_data.erase(client_id);
        return *this;
    }

    /** @brief Gets a constant reference to the current `RateLimitOptions`. */
    [[nodiscard]] const RateLimitOptions &
    get_options() const noexcept {
        return *_options;
    }

    /**
     * @brief Returns the number of clients currently tracked.
     *
     * Primarily useful for tests, telemetry, and diagnostics: it
     * reflects how many entries survived the last opportunistic
     * eviction pass. In production code, prefer driving behaviour from
     * the rate-limit response headers instead of this figure.
     */
    [[nodiscard]] std::size_t
    tracked_client_count() const noexcept {
        return _client_data.size();
    }

    /**
     * @brief Forces an immediate sweep of stale entries, on demand.
     *
     * Entries whose window has elapsed (i.e. the corresponding client
     * has been silent for at least one full window duration) are
     * removed. This is the same sweep that `process()` runs
     * opportunistically; exposing it here lets callers reclaim memory
     * proactively without waiting for the next periodic tick or for
     * the memory-pressure threshold to trip.
     *
     * @return Number of entries evicted.
     */
    std::size_t
    evict_stale_entries_now() {
        const auto before = _client_data.size();
        evict_stale_entries_internal(std::chrono::steady_clock::now());
        return before - _client_data.size();
    }

private:
    /** @brief Internal struct to store rate limit tracking data per client. */
    struct ClientData {
        size_t                                request_count   = 0; ///< Number of requests made in the current window.
        std::chrono::steady_clock::time_point last_reset_time = std::chrono::steady_clock::now();
        ///< Time when the window was last reset.
    };

    /**
     * @brief (Private) Evicts entries whose rate-limit window has already elapsed.
     *
     * "Stale" is defined as `now - entry.last_reset_time >= window`,
     * which is the exact condition that `process()` uses to reset a
     * client's counter: any entry matching it would, on its next
     * request, be reset to a fresh window anyway &mdash; so holding on
     * to it only burns memory. The sweep is O(N); it is gated by the
     * opportunistic schedule in `process()` so that the hot path stays
     * O(1) amortised.
     */
    void
    evict_stale_entries_internal(std::chrono::steady_clock::time_point now) noexcept {
        const auto window = _options->get_window();
        for (auto it = _client_data.begin(); it != _client_data.end();) {
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.last_reset_time) >= window) {
                it = _client_data.erase(it);
            } else {
                ++it;
            }
        }
    }

    std::shared_ptr<RateLimitOptions>          _options;     ///< Shared pointer to the rate limiting configuration.
    std::string                                _name;        ///< Name of this middleware instance.
    qb::unordered_map<std::string, ClientData> _client_data; ///< Stores request counts per client ID. Accessed from the owning listener only.
    /// Time point of the next scheduled periodic stale-entry sweep.
    /// Initialised lazily on the first call to `process()`; reset every
    /// time a sweep runs.
    std::chrono::steady_clock::time_point _next_cleanup_time{
        std::chrono::steady_clock::now() + rate_limit_security::STALE_ENTRY_CLEANUP_INTERVAL
    };

    /**
     * @brief (Private) Adds standard `X-RateLimit-*` headers to the HTTP response.
     * @param response The `Response` object to which headers will be added.
     * @param client_record The `ClientData` for the current client, used to calculate remaining requests and reset time.
     */
    void
    add_rate_limit_headers(Response &response, const ClientData &client_record) const {
        response.set_header("X-RateLimit-Limit", std::to_string(_options->get_max_requests()));

        size_t remaining_requests =
            (_options->get_max_requests() > client_record.request_count) ? (_options->get_max_requests() - client_record.request_count) : 0;
        response.set_header("X-RateLimit-Remaining", std::to_string(remaining_requests));

        auto now               = std::chrono::steady_clock::now();
        auto elapsed_in_window = std::chrono::duration_cast<std::chrono::milliseconds>(now - client_record.last_reset_time);
        auto time_until_reset  = _options->get_window() - elapsed_in_window;
        if (time_until_reset.count() < 0) {
            time_until_reset = qb::duration::zero();
        }
        response.set_header("X-RateLimit-Reset", std::to_string(std::chrono::duration_cast<std::chrono::seconds>(time_until_reset).count()));
    }
};

// --- Factory Functions ---

/**
 * @brief Creates a `std::shared_ptr` to a `RateLimitMiddleware` instance.
 * @tparam SessionType The session type used by the HTTP context.
 * @param options `RateLimitOptions` to configure the middleware. Defaults to default-constructed `RateLimitOptions`.
 * @param name An optional name for the middleware instance.
 * @return A `std::shared_ptr<RateLimitMiddleware<SessionType>>`.
 */
template <typename SessionType>
[[nodiscard]] std::shared_ptr<RateLimitMiddleware<SessionType>>
rate_limit_middleware(RateLimitOptions   options = RateLimitOptions(), // Pass by value for potential move
                      const std::string &name    = "RateLimitMiddleware") {
    return std::make_shared<RateLimitMiddleware<SessionType>>(std::move(options), name);
}

/**
 * @brief Creates a `RateLimitMiddleware` instance pre-configured with permissive options.
 * Suitable for development environments or internal services.
 * @tparam SessionType The session type.
 * @param name Optional name for the middleware instance.
 * @return `std::shared_ptr<RateLimitMiddleware<SessionType>>`.
 */
template <typename SessionType>
[[nodiscard]] std::shared_ptr<RateLimitMiddleware<SessionType>>
rate_limit_dev_middleware(const std::string &name = "DevRateLimitMiddleware") noexcept {
    return std::make_shared<RateLimitMiddleware<SessionType>>(RateLimitOptions::permissive(), name);
}

/**
 * @brief Creates a `RateLimitMiddleware` instance pre-configured with more secure, restrictive options.
 * Suitable as a baseline for production environments.
 * @tparam SessionType The session type.
 * @param name Optional name for the middleware instance.
 * @return `std::shared_ptr<RateLimitMiddleware<SessionType>>`.
 */
template <typename SessionType>
[[nodiscard]] std::shared_ptr<RateLimitMiddleware<SessionType>>
rate_limit_secure_middleware(const std::string &name = "SecureRateLimitMiddleware") noexcept {
    return std::make_shared<RateLimitMiddleware<SessionType>>(RateLimitOptions::secure(), name);
}
} // namespace qb::http

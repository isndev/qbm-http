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
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Middleware
 */
#pragma once

#include <chrono>      // For std::chrono::duration, minutes, milliseconds, steady_clock
#include <functional>  // For std::function
#include <memory>      // For std::shared_ptr, std::make_shared
#include <string>      // For std::string, std::to_string
#include <mutex>       // For std::mutex, std::lock_guard
#include <vector>      // For std::vector (used in RateLimitOptions setters indirectly)
#include <utility>     // For std::move

#include <qb/system/container/unordered_map.h> // For qb::unordered_map

#include "../routing/middleware.h" // For IMiddleware, Context, AsyncTaskResult
#include "../request.h"            // For qb::http::Request (used by Context)
#include "../response.h"           // For qb::http::Response (used by Context)
#include "../types.h"              // For qb::http::status enum

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
              , _message("Rate limit exceeded. Please try again later.") {
        }

        /**
         * @brief Sets the maximum number of requests allowed from a single client within the defined time window.
         * @param max_requests_val The maximum number of requests.
         * @return Reference to this `RateLimitOptions` instance for chaining.
         */
        RateLimitOptions &max_requests(size_t max_requests_val) noexcept {
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
        template<typename DurationRep, typename DurationPeriod>
        RateLimitOptions &window(const std::chrono::duration<DurationRep, DurationPeriod> &window_val) noexcept {
            _window = std::chrono::duration_cast<std::chrono::milliseconds>(window_val);
            return *this;
        }

        /**
         * @brief Sets the HTTP status code to be returned when a request is rate-limited.
         * @param status_code_val The `qb::http::status` enum value. Default is `qb::http::status::TOO_MANY_REQUESTS` (429).
         * @return Reference to this `RateLimitOptions` instance for chaining.
         */
        RateLimitOptions &status_code(qb::http::status status_code_val) noexcept {
            _status_code = status_code_val;
            return *this;
        }

        /**
         * @brief Sets the custom message for the response body when a request is rate-limited.
         * @param msg The message string. Passed by value for potential move.
         * @return Reference to this `RateLimitOptions` instance for chaining.
         */
        RateLimitOptions &message(std::string msg) {
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
        template<typename SessionType>
        RateLimitOptions &client_id_extractor(
            std::function<std::string(const Context<SessionType> &)> extractor) {
            // std::function assignment can allocate
            _client_id_extractor_fn =
                    [extractor_cb = std::move(extractor)](const void *ctx_ptr) -> std::string {
                        // This type erasure requires the caller of extract_client_id to pass the correct Context type.
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
        [[nodiscard]] static RateLimitOptions permissive() noexcept {
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
        [[nodiscard]] static RateLimitOptions secure() noexcept {
            return RateLimitOptions()
                    .max_requests(60) // Stricter limit
                    .window(std::chrono::minutes(1))
                    .message("Rate limit exceeded. Please try again later.");
        }

        // --- Getters ---
        [[nodiscard]] size_t get_max_requests() const noexcept { return _max_requests; }
        [[nodiscard]] std::chrono::milliseconds get_window() const noexcept { return _window; }
        [[nodiscard]] qb::http::status get_status_code() const noexcept { return _status_code; }
        [[nodiscard]] const std::string &get_message() const noexcept { return _message; }

        [[nodiscard]] bool has_custom_client_id_extractor() const noexcept {
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
        template<typename SessionType>
        [[nodiscard]] std::string extract_client_id(const Context<SessionType> &ctx) const {
            if (_client_id_extractor_fn) {
                try {
                    return _client_id_extractor_fn(static_cast<const void *>(&ctx));
                } catch (const std::bad_function_call & /*e*/) {
                    // Fallthrough to default if custom extractor fails (e.g. null after move)
                }
            }

            // Default extraction logic
            // TRequest::header returns String type, ensure conversion to std::string for processing.
            std::string client_id_str;
            const auto &header_val_obj = ctx.request().header("X-Forwarded-For");
            if constexpr (std::is_convertible_v<decltype(header_val_obj), std::string>) {
                client_id_str = header_val_obj;
            } else if constexpr (std::is_convertible_v<decltype(header_val_obj), std::string_view>) {
                client_id_str = std::string(header_val_obj);
            } else {
                // Fallback for custom String types
                client_id_str.assign(header_val_obj.data(), header_val_obj.length());
            }

            if (!client_id_str.empty()) {
                size_t comma_pos = client_id_str.find(',');
                if (comma_pos != std::string::npos) {
                    return client_id_str.substr(0, comma_pos); // Return the first IP in a list
                }
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
        size_t _max_requests;
        std::chrono::milliseconds _window;
        qb::http::status _status_code;
        std::string _message;
        std::function<std::string(const void *)> _client_id_extractor_fn; // Type-erased client ID extractor
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
     * Thread safety for request counting is managed internally using a `std::mutex`.
     *
     * @tparam SessionType The type of the session object managed by the router, used by `Context`.
     */
    template<typename SessionType>
    class RateLimitMiddleware : public IMiddleware<SessionType> {
    public:
        using ContextPtr = std::shared_ptr<Context<SessionType> >;

        /**
         * @brief Constructs `RateLimitMiddleware` with default `RateLimitOptions`.
         * @param name An optional name for this middleware instance (for logging/debugging).
         */
        explicit RateLimitMiddleware(std::string name = "RateLimitMiddleware") noexcept
            : _options(std::make_shared<RateLimitOptions>()), // Uses default RateLimitOptions
              _name(std::move(name)) {
        }

        /**
         * @brief Constructs `RateLimitMiddleware` with specified `RateLimitOptions`.
         * @param options The rate limiting configuration. Passed by value and moved.
         * @param name An optional name for this middleware instance.
         */
        explicit RateLimitMiddleware(
            RateLimitOptions options,
            std::string name = "RateLimitMiddleware"
        ) noexcept // Assuming make_shared and RateLimitOptions move ctor are noexcept
            : _options(std::make_shared<RateLimitOptions>(std::move(options))),
              _name(std::move(name)) {
        }

        /**
         * @brief Processes the incoming request, applying rate limiting logic.
         *
         * Extracts a client ID, checks if the request count for this ID exceeds the configured limit
         * within the time window. If rate-limited, sends an error response. Otherwise, increments
         * the count and allows the request to proceed. Sets `X-RateLimit-*` headers on the response.
         * @param ctx The shared `Context` for the current request.
         */
        void process(ContextPtr ctx) override {
            // Mutex locking is not noexcept
            const std::string client_id = _options->extract_client_id(*ctx);

            bool rate_limited_flag = false;
            ClientData client_data_for_headers; // To store data for headers outside lock

            {
                std::lock_guard<std::mutex> lock(_mutex); // Protect access to _client_data
                auto now = std::chrono::steady_clock::now();
                ClientData &current_client_record = _client_data[client_id]; // Creates if not exist

                // Check if the window has reset for this client
                if (std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - current_client_record.last_reset_time) >= _options->get_window()) {
                    current_client_record.request_count = 0;
                    current_client_record.last_reset_time = now;
                }

                if (current_client_record.request_count >= _options->get_max_requests()) {
                    rate_limited_flag = true;
                } else {
                    current_client_record.request_count++;
                }
                client_data_for_headers = current_client_record; // Copy data for header setting (outside lock)
            }

            add_rate_limit_headers(ctx->response(), client_data_for_headers);

            if (rate_limited_flag) {
                ctx->response().status() = _options->get_status_code();
                ctx->response().body() = _options->get_message(); // Assumes message is plain text or Body handles type
                ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                // Example, adjust if message is e.g. JSON
                ctx->complete(AsyncTaskResult::COMPLETE); // Stop processing
            } else {
                ctx->complete(AsyncTaskResult::CONTINUE); // Proceed to next middleware/handler
            }
        }

        /** @brief Gets the configured name of this middleware instance. */
        [[nodiscard]] std::string name() const noexcept override {
            return _name;
        }

        /** @brief Handles cancellation; currently a no-op for this middleware. */
        void cancel() noexcept override {
            // No specific asynchronous operations to cancel.
        }

        /**
         * @brief Resets rate limiting data for all tracked clients.
         * This clears all client request counts and effectively starts fresh windows for everyone.
         * @return Reference to this `RateLimitMiddleware` for chaining.
         */
        RateLimitMiddleware &reset_all_clients() {
            // Not noexcept due to lock
            std::lock_guard<std::mutex> lock(_mutex);
            _client_data.clear();
            return *this;
        }

        /**
         * @brief Resets rate limiting data for a specific client identifier.
         * @param client_id The identifier of the client whose rate limit data should be reset.
         * @return Reference to this `RateLimitMiddleware` for chaining.
         */
        RateLimitMiddleware &reset_client(const std::string &client_id) {
            // Not noexcept due to lock
            std::lock_guard<std::mutex> lock(_mutex);
            _client_data.erase(client_id);
            return *this;
        }

        /** @brief Gets a constant reference to the current `RateLimitOptions`. */
        [[nodiscard]] const RateLimitOptions &get_options() const noexcept {
            return *_options;
        }

    private:
        /** @brief Internal struct to store rate limit tracking data per client. */
        struct ClientData {
            size_t request_count = 0; ///< Number of requests made in the current window.
            std::chrono::steady_clock::time_point last_reset_time = std::chrono::steady_clock::now();
            ///< Time when the window was last reset.
        };

        std::shared_ptr<RateLimitOptions> _options; ///< Shared pointer to the rate limiting configuration.
        std::string _name; ///< Name of this middleware instance.
        mutable std::mutex _mutex; ///< Mutex to protect concurrent access to `_client_data`.
        mutable qb::unordered_map<std::string, ClientData> _client_data; ///< Stores request counts per client ID.

        /**
         * @brief (Private) Adds standard `X-RateLimit-*` headers to the HTTP response.
         * @param response The `Response` object to which headers will be added.
         * @param client_record The `ClientData` for the current client, used to calculate remaining requests and reset time.
         */
        void add_rate_limit_headers(Response &response, const ClientData &client_record) const {
            response.set_header("X-RateLimit-Limit", std::to_string(_options->get_max_requests()));

            size_t remaining_requests = (_options->get_max_requests() > client_record.request_count)
                                            ? (_options->get_max_requests() - client_record.request_count)
                                            : 0;
            response.set_header("X-RateLimit-Remaining", std::to_string(remaining_requests));

            auto now = std::chrono::steady_clock::now();
            auto elapsed_in_window = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - client_record.last_reset_time);
            auto time_until_reset_ms = _options->get_window() - elapsed_in_window;
            if (time_until_reset_ms.count() < 0) {
                time_until_reset_ms = std::chrono::milliseconds(0);
            }
            response.set_header("X-RateLimit-Reset",
                                std::to_string(
                                    std::chrono::duration_cast<std::chrono::seconds>(time_until_reset_ms).count()));
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
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<RateLimitMiddleware<SessionType> >
    rate_limit_middleware(
        RateLimitOptions options = RateLimitOptions(), // Pass by value for potential move
        const std::string &name = "RateLimitMiddleware"
    ) {
        return std::make_shared<RateLimitMiddleware<SessionType> >(std::move(options), name);
    }

    /**
     * @brief Creates a `RateLimitMiddleware` instance pre-configured with permissive options.
     * Suitable for development environments or internal services.
     * @tparam SessionType The session type.
     * @param name Optional name for the middleware instance.
     * @return `std::shared_ptr<RateLimitMiddleware<SessionType>>`.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<RateLimitMiddleware<SessionType> >
    rate_limit_dev_middleware(const std::string &name = "DevRateLimitMiddleware") noexcept {
        return std::make_shared<RateLimitMiddleware<SessionType> >(
            RateLimitOptions::permissive(), name);
    }

    /**
     * @brief Creates a `RateLimitMiddleware` instance pre-configured with more secure, restrictive options.
     * Suitable as a baseline for production environments.
     * @tparam SessionType The session type.
     * @param name Optional name for the middleware instance.
     * @return `std::shared_ptr<RateLimitMiddleware<SessionType>>`.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<RateLimitMiddleware<SessionType> >
    rate_limit_secure_middleware(const std::string &name = "SecureRateLimitMiddleware") noexcept {
        return std::make_shared<RateLimitMiddleware<SessionType> >(
            RateLimitOptions::secure(), name);
    }
} // namespace qb::http

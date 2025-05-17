#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <mutex>
#include <vector>

#include "../routing/middleware.h"
#include "../request.h"
#include "../response.h"
#include "../types.h"

namespace qb::http {

/**
 * @brief Configuration options for rate limiting HTTP requests.
 *
 * Allows defining maximum requests per time window, custom status codes and messages
 * for rate-limited responses, and a custom function to extract client identifiers.
 */
class RateLimitOptions {
public:
    /**
     * @brief Default constructor.
     * Initializes with 100 requests per 1-minute window, a 429 status code, 
     * and a default rate limit exceeded message.
     */
    RateLimitOptions()
        : _max_requests(100)
        , _window(std::chrono::minutes(1))
        , _status_code(HTTP_STATUS_TOO_MANY_REQUESTS)
        , _message("Rate limit exceeded. Please try again later.") {}

    /** @brief Sets the maximum number of requests allowed within the defined time window. */
    RateLimitOptions& max_requests(size_t max_requests_val) {
        _max_requests = max_requests_val;
        return *this;
    }
    /** @brief Sets the duration of the time window for rate limiting. */
    template <typename DurationRep, typename DurationPeriod>
    RateLimitOptions& window(const std::chrono::duration<DurationRep, DurationPeriod>& window_val) {
        _window = std::chrono::duration_cast<std::chrono::milliseconds>(window_val);
        return *this;
    }
    /** @brief Sets the HTTP status code to be returned when a request is rate-limited. */
    RateLimitOptions& status_code(http_status status_code_val) {
        _status_code = status_code_val;
        return *this;
    }
    /** @brief Sets the custom message for the response body when a request is rate-limited. */
    RateLimitOptions& message(const std::string& msg) {
        _message = msg;
        return *this;
    }

    /**
     * @brief Sets a custom function to extract a client identifier from the request context.
     * This identifier is used to track request counts for rate limiting.
     * @tparam SessionType The session type of the context.
     * @param extractor A function `std::string(const Context<SessionType>&)`.
     * @return Reference to this RateLimitOptions instance for chaining.
     */
    template <typename SessionType>
    RateLimitOptions& client_id_extractor(
        std::function<std::string(const Context<SessionType>&)> extractor) {
        _client_id_extractor_fn = 
            [extractor_cb = std::move(extractor)](const void* ctx_ptr) -> std::string {
                const auto* typed_ctx = static_cast<const Context<SessionType>*>(ctx_ptr);
                return extractor_cb(*typed_ctx);
            };
        return *this;
    }

    /** @brief Provides a permissive RateLimitOptions configuration, often used for development. */
    static RateLimitOptions permissive() {
        return RateLimitOptions()
            .max_requests(1000)
            .window(std::chrono::minutes(1))
            .message("You have reached the rate limit. Please try again later.");
    }
    /** @brief Provides a more restrictive RateLimitOptions configuration, suitable as a base for production. */
    static RateLimitOptions secure() {
        return RateLimitOptions()
            .max_requests(60)
            .window(std::chrono::minutes(1))
            .message("Rate limit exceeded. Please try again later.");
    }

    // Getters
    [[nodiscard]] size_t get_max_requests() const { return _max_requests; }
    [[nodiscard]] std::chrono::milliseconds get_window() const { return _window; }
    [[nodiscard]] http_status get_status_code() const { return _status_code; }
    [[nodiscard]] const std::string& get_message() const { return _message; }
    [[nodiscard]] bool has_custom_client_id_extractor() const { return static_cast<bool>(_client_id_extractor_fn); }

    /**
     * @brief Extracts the client identifier from the given context.
     * Uses a custom extractor if provided, otherwise falls back to checking common headers
     * like "X-Forwarded-For", or a placeholder session identifier.
     * @tparam SessionType The session type of the context.
     * @param ctx The request context.
     * @return A string representing the client identifier.
     */
    template <typename SessionType>
    [[nodiscard]] std::string extract_client_id(const Context<SessionType>& ctx) const {
        if (_client_id_extractor_fn) {
            return _client_id_extractor_fn(static_cast<const void*>(&ctx));
        }
        
        std::string client_id = std::string(ctx.request().header("X-Forwarded-For"));
        if (!client_id.empty()) {
            size_t comma_pos = client_id.find(',');
            if (comma_pos != std::string::npos) {
                client_id = client_id.substr(0, comma_pos);
            }
            return client_id;
        }
        
        if (ctx.session()) {
            return "session_placeholder_id:" + std::to_string(reinterpret_cast<uintptr_t>(ctx.session().get()));
        }
        return "unknown_client";
    }

private:
    size_t _max_requests;
    std::chrono::milliseconds _window;
    http_status _status_code;
    std::string _message;
    std::function<std::string(const void*)> _client_id_extractor_fn;
};

/**
 * @brief Middleware to limit the rate of requests from clients.
 *
 * Tracks requests per client identifier (e.g., IP address) within a configured time window.
 * If a client exceeds the maximum allowed requests, subsequent requests are rejected
 * with a configurable HTTP status code and message. Standard rate limit headers
 * (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset) are added to responses.
 *
 * @tparam SessionType The type of the session object managed by the router.
 */
template <typename SessionType>
class RateLimitMiddleware : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;
    
    /** @brief Constructs RateLimitMiddleware with default options. */
    RateLimitMiddleware(std::string name = "RateLimitMiddleware") 
        : _options(std::make_shared<RateLimitOptions>()),
          _name(std::move(name)) {}
    
    /** 
     * @brief Constructs RateLimitMiddleware with specified options.
     * @param options The rate limiting configuration.
     * @param name An optional name for this middleware instance.
     */
    explicit RateLimitMiddleware(
        const RateLimitOptions& options,
        std::string name = "RateLimitMiddleware"
    ) : _options(std::make_shared<RateLimitOptions>(options)), 
        _name(std::move(name)) {}
    
    /**
     * @brief Handles the incoming request, applying rate limiting logic.
     * @param ctx The shared context for the current request.
     */
    void process(ContextPtr ctx) override {
        const std::string client_id = _options->extract_client_id(*ctx);
        
        bool rate_limited = false;
        ClientData client_data_snapshot;

        {
            std::lock_guard<std::mutex> lock(_mutex);
            auto now = std::chrono::steady_clock::now();
            ClientData& client_data_ref = _client_data[client_id]; 

            if (std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - client_data_ref.last_reset) >= _options->get_window()) {
                client_data_ref.count = 0;
                client_data_ref.last_reset = now;
            }

            if (client_data_ref.count >= _options->get_max_requests()) {
                rate_limited = true;
            } else {
                client_data_ref.count++;
            }
            client_data_snapshot = client_data_ref;
        }

        add_rate_limit_headers(ctx->response(), client_data_snapshot);

        if (rate_limited) {
            ctx->response().status_code = _options->get_status_code();
            ctx->response().body() = _options->get_message();
            ctx->complete(AsyncTaskResult::COMPLETE);
        } else {
            ctx->complete(AsyncTaskResult::CONTINUE);
        }
    }
    
    /** @brief Gets the name of this middleware instance. */
    std::string name() const override {
        return _name;
    }

    /** @brief Handles cancellation; a no-op for this middleware. */
    void cancel() override { /* No-op */ }
    
    /** @brief Resets rate limiting data for all clients. */
    RateLimitMiddleware& reset_all_clients() {
        std::lock_guard<std::mutex> lock(_mutex);
        _client_data.clear();
        return *this;
    }
    
    /** @brief Resets rate limiting data for a specific client. */
    RateLimitMiddleware& reset_client(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(_mutex);
        _client_data.erase(client_id);
        return *this;
    }

    /** @brief Gets the current rate limiting options. */
    const RateLimitOptions& get_options() const { return *_options; }
    
private:
    struct ClientData {
        size_t count = 0;
        std::chrono::steady_clock::time_point last_reset = std::chrono::steady_clock::now();
    };

    std::shared_ptr<RateLimitOptions> _options;
    std::string _name;
    mutable std::mutex _mutex; 
    mutable qb::unordered_map<std::string, ClientData> _client_data;

    /** @brief Adds standard rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset) to the response. */
    void add_rate_limit_headers(Response& response, const ClientData& client_data) const {
        response.set_header("X-RateLimit-Limit", std::to_string(_options->get_max_requests()));
        response.set_header("X-RateLimit-Remaining", 
            std::to_string(_options->get_max_requests() > client_data.count ? 
                (_options->get_max_requests() - client_data.count) : 0));
        
        auto now = std::chrono::steady_clock::now();
        auto time_in_window = std::chrono::duration_cast<std::chrono::milliseconds>(now - client_data.last_reset);
        auto reset_after_ms = _options->get_window() - time_in_window;
        if (reset_after_ms.count() < 0) reset_after_ms = std::chrono::milliseconds(0);
        
        response.set_header("X-RateLimit-Reset", 
            std::to_string(std::chrono::duration_cast<std::chrono::seconds>(reset_after_ms).count()));
    }
};

/**
 * @brief Creates a RateLimitMiddleware instance with specified or default options.
 * @tparam SessionType The session type.
 * @param options Rate limiting configuration options.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created RateLimitMiddleware.
 */
template <typename SessionType>
std::shared_ptr<RateLimitMiddleware<SessionType>>
rate_limit_middleware(const RateLimitOptions& options = RateLimitOptions(), const std::string& name = "RateLimitMiddleware") {
    return std::make_shared<RateLimitMiddleware<SessionType>>(options, name);
}

/**
 * @brief Creates a RateLimitMiddleware instance with permissive options, suitable for development.
 * @tparam SessionType The session type.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created RateLimitMiddleware.
 */
template <typename SessionType>
std::shared_ptr<RateLimitMiddleware<SessionType>>
rate_limit_dev_middleware(const std::string& name = "DevRateLimitMiddleware") {
    return std::make_shared<RateLimitMiddleware<SessionType>>(
        RateLimitOptions::permissive(), name);
}

/**
 * @brief Creates a RateLimitMiddleware instance with secure options, suitable as a base for production.
 * @tparam SessionType The session type.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created RateLimitMiddleware.
 */
template <typename SessionType>
std::shared_ptr<RateLimitMiddleware<SessionType>>
rate_limit_secure_middleware(const std::string& name = "SecureRateLimitMiddleware") {
    return std::make_shared<RateLimitMiddleware<SessionType>>(
        RateLimitOptions::secure(), name);
}

} // namespace qb::http 
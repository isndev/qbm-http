#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <mutex>
#include "../routing/context.h"
#include "../http.h"

namespace qb::http {

/**
 * @brief Rate limiting configuration
 */
class RateLimitOptions {
public:
    /**
     * @brief Default constructor with common settings
     */
    RateLimitOptions()
        : _max_requests(100)
        , _window(std::chrono::minutes(1))
        , _status_code(HTTP_STATUS_TOO_MANY_REQUESTS) {}

    /**
     * @brief Set maximum requests per time window
     * @param max_requests Maximum number of requests allowed
     * @return Reference to this options object for chaining
     */
    RateLimitOptions& max_requests(size_t max_requests) {
        _max_requests = max_requests;
        return *this;
    }

    /**
     * @brief Set time window
     * @param window Duration of the time window
     * @return Reference to this options object for chaining
     */
    template <typename Duration>
    RateLimitOptions& window(Duration window) {
        _window = std::chrono::duration_cast<std::chrono::milliseconds>(window);
        return *this;
    }

    /**
     * @brief Set HTTP status code for rate limit errors
     * @param status_code HTTP status code
     * @return Reference to this options object for chaining
     */
    RateLimitOptions& status_code(http_status status_code) {
        _status_code = status_code;
        return *this;
    }

    /**
     * @brief Set error message for rate limit errors
     * @param message Error message
     * @return Reference to this options object for chaining
     */
    RateLimitOptions& message(const std::string& message) {
        _message = message;
        return *this;
    }

    /**
     * @brief Set custom client ID extractor
     * @param extractor Function to extract client ID from context
     * @return Reference to this options object for chaining
     */
    template <typename Session, typename String>
    RateLimitOptions& client_id_extractor(
        std::function<std::string(const RouterContext<Session, String>&)> extractor) {
        _client_id_extractor_ptr = std::make_shared<
            std::function<std::string(const void*)>>(
            [extractor](const void* ctx_ptr) {
                auto& ctx = *static_cast<const RouterContext<Session, String>*>(ctx_ptr);
                return extractor(ctx);
            });
        return *this;
    }

    /**
     * @brief Create permissive rate limit options for development
     * @return Rate limit options with permissive settings
     */
    static RateLimitOptions dev() {
        return RateLimitOptions()
            .max_requests(1000)
            .window(std::chrono::minutes(1));
    }

    /**
     * @brief Create secure rate limit options for production
     * @return Rate limit options with secure settings
     */
    static RateLimitOptions secure() {
        return RateLimitOptions()
            .max_requests(60)
            .window(std::chrono::minutes(1))
            .message("Rate limit exceeded. Please try again later.");
    }

    // Getters
    [[nodiscard]] size_t max_requests() const { return _max_requests; }
    [[nodiscard]] std::chrono::milliseconds window() const { return _window; }
    [[nodiscard]] http_status status_code() const { return _status_code; }
    [[nodiscard]] const std::string& message() const { return _message; }
    [[nodiscard]] bool has_custom_extractor() const { return _client_id_extractor_ptr != nullptr; }

    /**
     * @brief Extract client ID from context
     * @param ctx_ptr Pointer to context
     * @return Client ID
     */
    template <typename Session, typename String>
    [[nodiscard]] std::string extract_client_id(const RouterContext<Session, String>& ctx) const {
        if (_client_id_extractor_ptr) {
            return (*_client_id_extractor_ptr)(&ctx);
        }

        // Default extraction logic: X-Forwarded-For or client IP
        std::string client_id = ctx.header("X-Forwarded-For");
        if (client_id.empty()) {
            // Try to get IP from the session if available
            if constexpr (has_get_client_ip_method<Session>::value) {
                return ctx.session->get_client_ip();
            } else if constexpr (has_remote_endpoint_method<Session>::value) {
                return ctx.session->remote_endpoint();
            } else {
                // Use session ID as a fallback
                if constexpr (has_id_method<Session>::value) {
                    return ctx.session->id().to_string();
                } else {
                    // Last resort: use pointer address as a string
                    return std::to_string(reinterpret_cast<std::uintptr_t>(ctx.session.get()));
                }
            }
        }
        return client_id;
    }

private:
    size_t _max_requests;
    std::chrono::milliseconds _window;
    http_status _status_code;
    std::string _message = "Rate limit exceeded";
    std::shared_ptr<std::function<std::string(const void*)>> _client_id_extractor_ptr;

    // Type traits to check for methods
    template <typename S, typename = void>
    struct has_get_client_ip_method : std::false_type {};

    template <typename S>
    struct has_get_client_ip_method<S, std::void_t<decltype(std::declval<S>().get_client_ip())>>
        : std::true_type {};

    template <typename S, typename = void>
    struct has_remote_endpoint_method : std::false_type {};

    template <typename S>
    struct has_remote_endpoint_method<S, std::void_t<decltype(std::declval<S>().remote_endpoint())>>
        : std::true_type {};

    template <typename S, typename = void>
    struct has_id_method : std::false_type {};

    template <typename S>
    struct has_id_method<S, std::void_t<decltype(std::declval<S>().id())>>
        : std::true_type {};
};

/**
 * @brief Rate limiting middleware for HTTP requests
 * 
 * This class provides rate limiting functionality based on client ID
 * (typically IP address) to prevent abuse.
 * 
 * @tparam Session HTTP session type
 * @tparam String String type (std::string or std::string_view)
 */
template <typename Session, typename String = std::string>
class RateLimit {
public:
    using Context = RouterContext<Session, String>;
    using Request = TRequest<String>;
    using Response = TResponse<String>;

    /**
     * @brief Default constructor with default options
     */
    RateLimit() : _options(std::make_shared<RateLimitOptions>()) {}

    /**
     * @brief Constructor with custom rate limit options
     * @param options Rate limit options
     */
    explicit RateLimit(const RateLimitOptions& options)
        : _options(std::make_shared<RateLimitOptions>(options)) {}

    /**
     * @brief Constructor with direct parameters
     * @param max_requests Maximum requests per window
     * @param window Time window
     */
    template <typename Duration>
    RateLimit(size_t max_requests, Duration window)
        : _options(std::make_shared<RateLimitOptions>()) {
        _options->max_requests(max_requests)
                .window(window);
    }

    /**
     * @brief Check if request is rate limited
     * @param ctx Router context
     * @return true if the request should continue, false if rate limited
     */
    bool apply(Context& ctx) const {
        const std::string client_id = _options->extract_client_id(ctx);
        
        {
            std::lock_guard<std::mutex> lock(_mutex);
            auto now = std::chrono::steady_clock::now();
            auto& client_data = _client_data[client_id];

            // Reset counter if the window has expired
            if (std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - client_data.last_reset) > _options->window()) {
                client_data.count = 0;
                client_data.last_reset = now;
            }

            // Check if rate limit is exceeded
            if (client_data.count >= _options->max_requests()) {
                // Rate limit exceeded, send error response
                ctx.response.status_code = _options->status_code();
                ctx.response.body() = _options->message();
                
                // Add rate limit headers
                add_rate_limit_headers(ctx, client_data);
                
                // Mark as handled
                ctx.mark_handled();
                return false;
            }

            // Increment request counter
            client_data.count++;
            
            // Add rate limit headers
            add_rate_limit_headers(ctx, client_data);
        }

        return true;
    }

    /**
     * @brief Create middleware function for the router
     * @return Middleware function
     */
    auto middleware() const {
        return [this](Context& ctx) {
            return apply(ctx);
        };
    }

    /**
     * @brief Get options
     * @return Reference to rate limit options
     */
    const RateLimitOptions& options() const {
        return *_options;
    }

    /**
     * @brief Update rate limit options
     * @param options New options
     * @return Reference to this rate limiter
     */
    RateLimit& update_options(const RateLimitOptions& options) {
        _options = std::make_shared<RateLimitOptions>(options);
        return *this;
    }

    /**
     * @brief Reset rate limiter data
     */
    void reset() {
        std::lock_guard<std::mutex> lock(_mutex);
        _client_data.clear();
    }

    /**
     * @brief Reset rate limit for a specific client
     * @param client_id Client ID
     */
    void reset_client(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(_mutex);
        _client_data.erase(client_id);
    }

private:
    struct ClientData {
        size_t count = 0;
        std::chrono::steady_clock::time_point last_reset = std::chrono::steady_clock::now();
    };

    std::shared_ptr<RateLimitOptions> _options;
    mutable std::mutex _mutex;
    mutable std::map<std::string, ClientData> _client_data;

    /**
     * @brief Add rate limit headers to the response
     * @param ctx Router context
     * @param client_data Client rate limit data
     */
    void add_rate_limit_headers(Context& ctx, const ClientData& client_data) const {
        // Add standard rate limit headers
        ctx.response.add_header("X-RateLimit-Limit", std::to_string(_options->max_requests()));
        ctx.response.add_header("X-RateLimit-Remaining", 
            std::to_string(_options->max_requests() > client_data.count ? 
                _options->max_requests() - client_data.count : 0));
        
        // Calculate reset time
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - client_data.last_reset);
        auto reset_after = _options->window() - elapsed;
        if (reset_after.count() < 0) reset_after = std::chrono::milliseconds(0);
        
        ctx.response.add_header("X-RateLimit-Reset", 
            std::to_string(reset_after.count() / 1000));  // In seconds
    }
};

/**
 * @brief Create a rate limiter with default options
 * @return Rate limiter instance
 */
template <typename Session, typename String = std::string>
inline auto create_rate_limit() {
    return RateLimit<Session, String>();
}

/**
 * @brief Create a rate limiter with custom options
 * @param options Rate limit options
 * @return Rate limiter instance
 */
template <typename Session, typename String = std::string>
inline auto create_rate_limit(const RateLimitOptions& options) {
    return RateLimit<Session, String>(options);
}

/**
 * @brief Create a rate limiter middleware function
 * @param options Rate limit options
 * @return Middleware function
 */
template <typename Session, typename String = std::string>
inline auto rate_limit_middleware(const RateLimitOptions& options) {
    return RateLimit<Session, String>(options).middleware();
}

} // namespace qb::http 
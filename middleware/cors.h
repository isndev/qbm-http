#pragma once

#include <memory>
#include <functional>
#include <string>
#include <vector>
#include <algorithm>
#include <regex>
#include <qb/system/container/unordered_map.h>
#include "./middleware_interface.h"

namespace qb::http {

/**
 * @brief Advanced CORS (Cross-Origin Resource Sharing) configuration options
 */
class CorsOptions {
public:
    /**
     * @brief Allow credentials setting for CORS
     */
    enum class AllowCredentials {
        No, ///< Do not allow credentials
        Yes ///< Allow credentials
    };

    /**
     * @brief Origin matching strategy
     */
    enum class OriginMatchStrategy {
        Exact,   ///< Exact string matching (default)
        Regex,   ///< Regular expression matching
        Function ///< Use custom function for matching
    };

    /**
     * @brief Default constructor
     */
    CorsOptions() = default;

    /**
     * @brief Constructor with origins
     * @param origins List of allowed origins
     */
    explicit CorsOptions(std::vector<std::string> origins)
        : _origins(std::move(origins)) {}

    /**
     * @brief Set allowed origins
     * @param origins List of allowed origins
     * @return Reference to this options object
     */
    CorsOptions& origins(std::vector<std::string> origins) {
        _origins = std::move(origins);
        _match_strategy = OriginMatchStrategy::Exact;
        return *this;
    }

    /**
     * @brief Set regex patterns for allowed origins
     * @param patterns List of regex patterns for allowed origins
     * @return Reference to this options object
     */
    CorsOptions& origin_patterns(std::vector<std::string> patterns) {
        _origins = std::move(patterns);
        _match_strategy = OriginMatchStrategy::Regex;
        _patterns_compiled = false;
        return *this;
    }

    /**
     * @brief Set a custom function for origin matching
     * @param matcher Function that takes an origin string and returns true if allowed
     * @return Reference to this options object
     */
    CorsOptions& origin_matcher(std::function<bool(const std::string&)> matcher) {
        _origin_matcher = std::move(matcher);
        _match_strategy = OriginMatchStrategy::Function;
        return *this;
    }

    /**
     * @brief Set allowed methods
     * @param methods List of allowed methods
     * @return Reference to this options object
     */
    CorsOptions& methods(std::vector<std::string> methods) {
        _methods = std::move(methods);
        return *this;
    }

    /**
     * @brief Enable all common HTTP methods
     * @return Reference to this options object
     */
    CorsOptions& all_methods() {
        _methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"};
        return *this;
    }

    /**
     * @brief Set allowed headers
     * @param headers List of allowed headers
     * @return Reference to this options object
     */
    CorsOptions& headers(std::vector<std::string> headers) {
        _headers = std::move(headers);
        return *this;
    }

    /**
     * @brief Enable all commonly used headers
     * @return Reference to this options object
     */
    CorsOptions& common_headers() {
        _headers = {
            "Accept", "Accept-Language", "Content-Language", "Content-Type",
            "Authorization", "X-Requested-With", "Origin", "DNT",
            "User-Agent", "X-Forwarded-For", "If-Modified-Since",
            "Cache-Control", "Range"
        };
        return *this;
    }

    /**
     * @brief Set headers to expose
     * @param headers List of headers to expose
     * @return Reference to this options object
     */
    CorsOptions& expose(std::vector<std::string> headers) {
        _expose_headers = std::move(headers);
        return *this;
    }

    /**
     * @brief Set whether to allow credentials
     * @param allow Whether to allow credentials
     * @return Reference to this options object
     */
    CorsOptions& credentials(AllowCredentials allow) {
        _credentials = allow;
        return *this;
    }

    /**
     * @brief Set max age for preflight requests
     * @param age Max age in seconds
     * @return Reference to this options object
     */
    CorsOptions& age(int age) {
        _max_age = age;
        return *this;
    }

    /**
     * @brief Create a permissive CORS configuration for development
     * @return CorsOptions with permissive settings
     */
    static CorsOptions permissive() {
        return CorsOptions()
            .origins({"*"})
            .all_methods()
            .common_headers()
            .credentials(AllowCredentials::Yes)
            .expose({"Content-Length", "X-Request-Id", "X-Response-Time"});
    }

    /**
     * @brief Create a secure CORS configuration for production
     * @param allowed_origins List of specific allowed origins
     * @return CorsOptions with secure settings
     */
    static CorsOptions secure(const std::vector<std::string>& allowed_origins) {
        return CorsOptions()
            .origins(allowed_origins)
            .methods({"GET", "POST", "OPTIONS"})
            .headers({"Content-Type", "Authorization"})
            .credentials(AllowCredentials::No)
            .age(3600); // 1 hour
    }

    /**
     * @brief Check if a specific origin is allowed
     * @param origin Origin to check
     * @return true if the origin is allowed, false otherwise
     */
    bool is_origin_allowed(const std::string& origin) const {
        if (_origins.empty()) {
            return false;
        }

        switch (_match_strategy) {
            case OriginMatchStrategy::Exact:
                // Check for wildcard or exact match
                if (std::find(_origins.begin(), _origins.end(), "*") != _origins.end()) {
                    return true;
                }
                return std::find(_origins.begin(), _origins.end(), origin) != _origins.end();

            case OriginMatchStrategy::Regex:
                ensure_patterns_compiled();
                for (const auto& pattern : _regex_patterns) {
                    if (std::regex_match(origin, pattern)) {
                        return true;
                    }
                }
                return false;

            case OriginMatchStrategy::Function:
                return _origin_matcher && _origin_matcher(origin);

            default:
                return false;
        }
    }

    /**
     * @brief Check if all origins are allowed
     * @return true if all origins are allowed, false otherwise
     */
    bool allow_all_origins() const {
        return _match_strategy == OriginMatchStrategy::Exact &&
               std::find(_origins.begin(), _origins.end(), "*") != _origins.end();
    }

    /**
     * @brief Get list of allowed origins
     * @return List of allowed origins
     */
    const std::vector<std::string>& origins() const {
        return _origins;
    }

    /**
     * @brief Get list of allowed methods
     * @return List of allowed methods
     */
    const std::vector<std::string>& allowed_methods() const {
        return _methods;
    }

    /**
     * @brief Get list of allowed headers
     * @return List of allowed headers
     */
    const std::vector<std::string>& allowed_headers() const {
        return _headers;
    }

    /**
     * @brief Get list of exposed headers
     * @return List of exposed headers
     */
    const std::vector<std::string>& exposed_headers() const {
        return _expose_headers;
    }

    /**
     * @brief Get whether to allow credentials
     * @return Allow credentials setting
     */
    AllowCredentials allow_credentials() const {
        return _credentials;
    }

    /**
     * @brief Get max age for preflight requests
     * @return Max age in seconds
     */
    int max_age() const {
        return _max_age;
    }

    /**
     * @brief Get the origin matching strategy
     * @return Origin matching strategy
     */
    OriginMatchStrategy match_strategy() const {
        return _match_strategy;
    }

private:
    std::vector<std::string> _origins; ///< List of allowed origins
    std::vector<std::string> _methods; ///< List of allowed methods
    std::vector<std::string> _headers; ///< List of allowed headers
    std::vector<std::string> _expose_headers; ///< List of headers to expose
    AllowCredentials _credentials = AllowCredentials::No; ///< Whether to allow credentials
    int _max_age = 86400; ///< Max age for preflight requests in seconds (default: 24 hours)
    OriginMatchStrategy _match_strategy = OriginMatchStrategy::Exact; ///< Origin matching strategy
    std::function<bool(const std::string&)> _origin_matcher; ///< Custom origin matcher function

    // Cache for compiled regex patterns (only used with Regex strategy)
    mutable std::vector<std::regex> _regex_patterns;
    mutable bool _patterns_compiled = false;

    /**
     * @brief Compile regex patterns if needed
     */
    void ensure_patterns_compiled() const {
        if (!_patterns_compiled && _match_strategy == OriginMatchStrategy::Regex) {
            _regex_patterns.clear();
            for (const auto& pattern : _origins) {
                try {
                    _regex_patterns.emplace_back(pattern);
                } catch (const std::regex_error&) {
                    // Skip invalid patterns
                }
            }
            _patterns_compiled = true;
        }
    }
};

/**
 * @brief Utility function to join strings with a separator
 */
template <typename String = std::string>
String join(const std::vector<String>& elements, const String& separator) {
    if (elements.empty()) {
        return "";
    }
    
    String result = elements[0];
    for (size_t i = 1; i < elements.size(); ++i) {
        result += separator + elements[i];
    }
    
    return result;
}

/**
 * @brief Advanced middleware for handling Cross-Origin Resource Sharing (CORS)
 * 
 * This middleware provides comprehensive CORS support including:
 * - Origin validation using exact match, regex patterns, or custom functions
 * - Preflight request handling
 * - Support for credentials
 * - Configurable headers and methods
 * - Cache control through max-age
 */
template <typename Session, typename String = std::string>
class CorsMiddleware : public ISyncMiddleware<Session, String> {
public:
    using Context = typename ISyncMiddleware<Session, String>::Context;
    
    /**
     * @brief Default constructor with permissive options (for development)
     */
    CorsMiddleware() 
        : _options(std::make_shared<CorsOptions>(CorsOptions::permissive())),
          _name("CorsMiddleware") {}
    
    /**
     * @brief Constructor with custom CORS options
     * @param options CORS options to use
     * @param name Middleware name
     */
    explicit CorsMiddleware(const CorsOptions& options, std::string name = "CorsMiddleware")
        : _options(std::make_shared<CorsOptions>(options)), 
          _name(std::move(name)) {}
    
    /**
     * @brief Create a permissive CORS middleware for development
     * @return CorsMiddleware instance with permissive settings
     */
    static CorsMiddleware dev(const std::string& name = "DevCorsMiddleware") {
        return CorsMiddleware(CorsOptions::permissive(), name);
    }
    
    /**
     * @brief Create a secure CORS middleware for production
     * @param allowed_origins List of allowed origins
     * @return CorsMiddleware instance with secure settings
     */
    static CorsMiddleware secure(
        const std::vector<std::string>& allowed_origins,
        const std::string& name = "SecureCorsMiddleware"
    ) {
        return CorsMiddleware(CorsOptions::secure(allowed_origins), name);
    }
    
    /**
     * @brief Process a request
     * @param ctx Request context
     * @return Middleware result
     */
    MiddlewareResult process(Context& ctx) override {
        const auto& origin = ctx.request.header("Origin");

        // If no Origin header, just continue
        if (origin.empty()) {
            return MiddlewareResult::Continue();
        }

        bool origin_allowed = false;
        bool using_wildcard = false;

        // Check if origin is allowed and determine response header
        if (_options->allow_all_origins() &&
            _options->match_strategy() != CorsOptions::OriginMatchStrategy::Function &&
            _options->allow_credentials() != CorsOptions::AllowCredentials::Yes) {
            // For wildcard origins without custom function and without credentials,
            // we can use "*"
            origin_allowed = true;
            using_wildcard = true;
            ctx.response.add_header("Access-Control-Allow-Origin", "*");
        } else if (_options->is_origin_allowed(origin)) {
            // For specific origins, origins with custom matcher,
            // or with credentials, we must return the exact origin
            origin_allowed = true;
            using_wildcard = false;
            ctx.response.add_header("Access-Control-Allow-Origin", origin);

            // If credentials are allowed, add the header
            if (_options->allow_credentials() == CorsOptions::AllowCredentials::Yes) {
                ctx.response.add_header("Access-Control-Allow-Credentials", "true");
            }
        }

        // Set Vary header to indicate the response depends on Origin
        // This is important for caching
        ctx.response.add_header("Vary", "Origin");

        // If origin is not allowed, continue without CORS headers
        if (!origin_allowed) {
            return MiddlewareResult::Continue();
        }

        // For preflight requests
        if (ctx.request.method == HTTP_OPTIONS) {
            const auto& request_method = ctx.request.header("Access-Control-Request-Method");
            if (!request_method.empty()) {
                // Add allowed methods
                const auto& allowed_methods = _options->allowed_methods();
                if (!allowed_methods.empty()) {
                    ctx.response.add_header("Access-Control-Allow-Methods",
                                        join(allowed_methods, String(", ")));
                } else {
                    // Default to common methods if none specified
                    ctx.response.add_header("Access-Control-Allow-Methods",
                                        "GET, POST, PUT, DELETE, HEAD, OPTIONS");
                }

                // Add allowed headers
                const auto& allowed_headers = _options->allowed_headers();
                if (!allowed_headers.empty()) {
                    ctx.response.add_header("Access-Control-Allow-Headers",
                                        join(allowed_headers, String(", ")));
                } else {
                    // Default to common headers if none specified
                    ctx.response.add_header("Access-Control-Allow-Headers",
                                        "Content-Type, Authorization");
                }

                // Get requested headers
                const auto& requested_headers =
                    ctx.request.header("Access-Control-Request-Headers");
                if (!requested_headers.empty()) {
                    // Update Vary header to include Access-Control-Request-Headers
                    ctx.response.set_header("Vary",
                                        "Origin, Access-Control-Request-Headers");
                }

                // Add max age
                ctx.response.add_header("Access-Control-Max-Age",
                                    std::to_string(_options->max_age()));

                // Set response for preflight
                ctx.response.status_code = HTTP_STATUS_NO_CONTENT; // No Content
                ctx.mark_handled();

                return MiddlewareResult::Stop(); // Skip the rest of middleware chain for preflight
            }
        }

        // For normal requests, add exposed headers if any
        const auto& exposed_headers = _options->exposed_headers();
        if (!exposed_headers.empty()) {
            ctx.response.add_header("Access-Control-Expose-Headers",
                                join(exposed_headers, String(", ")));
        }

        // Continue with the request processing
        return MiddlewareResult::Continue();
    }
    
    /**
     * @brief Get the middleware name
     */
    std::string name() const override {
        return _name;
    }
    
    /**
     * @brief Get current CORS options
     * @return Reference to the CORS options
     */
    const CorsOptions& options() const {
        return *_options;
    }
    
    /**
     * @brief Update CORS options
     * @param options New CORS options
     * @return Reference to this middleware
     */
    CorsMiddleware& update_options(const CorsOptions& options) {
        _options = std::make_shared<CorsOptions>(options);
        return *this;
    }
    
private:
    std::shared_ptr<CorsOptions> _options;
    std::string _name;
};

/**
 * @brief Create a CORS middleware with default permissive options
 * @return CORS middleware adapter with permissive settings (for development)
 */
template <typename Session, typename String = std::string>
auto cors_middleware() {
    auto middleware = std::make_shared<CorsMiddleware<Session, String>>();
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create a CORS middleware with custom options
 * @param options CORS options to use
 * @param name Middleware name
 * @return CORS middleware adapter with the specified options
 */
template <typename Session, typename String = std::string>
auto cors_middleware(
    const CorsOptions& options,
    const std::string& name = "CorsMiddleware"
) {
    auto middleware = std::make_shared<CorsMiddleware<Session, String>>(options, name);
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create a CORS middleware with permissive options for development
 * @param name Middleware name
 * @return CORS middleware adapter with permissive settings
 */
template <typename Session, typename String = std::string>
auto cors_dev_middleware(const std::string& name = "DevCorsMiddleware") {
    auto middleware = std::make_shared<CorsMiddleware<Session, String>>(
        CorsOptions::permissive(), name);
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create a CORS middleware with secure options for production
 * @param allowed_origins List of allowed origins
 * @param name Middleware name
 * @return CORS middleware adapter with secure settings
 */
template <typename Session, typename String = std::string>
auto cors_secure_middleware(
    const std::vector<std::string>& allowed_origins,
    const std::string& name = "SecureCorsMiddleware"
) {
    auto middleware = std::make_shared<CorsMiddleware<Session, String>>(
        CorsOptions::secure(allowed_origins), name);
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

} // namespace qb::http 
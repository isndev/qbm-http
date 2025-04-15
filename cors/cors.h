#pragma once

#include <memory>
#include <functional>
#include <string>
#include "./cors_options.h"
#include "../request.h"
#include "../response.h"
#include "../routing/context.h"
#include "../utility.h"

namespace qb::http {

/**
 * @brief CORS (Cross-Origin Resource Sharing) handler
 * 
 * This class provides functionality for handling CORS requests,
 * including preflight requests and applying CORS headers to responses.
 * It can be used either directly or as middleware in a router.
 * 
 * @tparam Session HTTP session type
 * @tparam String String type (std::string or std::string_view)
 */
template <typename Session, typename String = std::string>
class Cors {
public:
    using Context = RouterContext<Session, String>;
    using Request = TRequest<String>;
    using Response = TResponse<String>;
    
    /**
     * @brief Default constructor with default options
     */
    Cors() : _options(std::make_shared<CorsOptions>()) {}
    
    /**
     * @brief Constructor with custom CORS options
     * @param options CORS options to use
     */
    explicit Cors(const CorsOptions& options) 
        : _options(std::make_shared<CorsOptions>(options)) {}
    
    /**
     * @brief Constructor with regex patterns for matching origins
     * @param regex_patterns List of regex patterns for allowed origins
     * @param methods Allowed HTTP methods
     * @param headers Allowed request headers
     * @param allow_credentials Whether to allow credentials
     */
    Cors(const std::vector<std::string>& regex_patterns,
         const std::vector<std::string>& methods = {},
         const std::vector<std::string>& headers = {},
         bool allow_credentials = false)
        : _options(std::make_shared<CorsOptions>()) {
        _options->origin_patterns(regex_patterns)
                .methods(methods)
                .headers(headers)
                .credentials(allow_credentials ? 
                    CorsOptions::AllowCredentials::Yes : 
                    CorsOptions::AllowCredentials::No);
    }
    
    /**
     * @brief Create a permissive CORS handler for development
     * @return Cors instance with permissive settings
     */
    static Cors dev() {
        return Cors(CorsOptions::permissive());
    }
    
    /**
     * @brief Create a secure CORS handler for production
     * @param allowed_origins List of specific allowed origins
     * @return Cors instance with secure settings
     */
    static Cors secure(const std::vector<std::string>& allowed_origins) {
        return Cors(CorsOptions::secure(allowed_origins));
    }
    
    /**
     * @brief Apply CORS configuration to a request/response
     * 
     * This is the main method that processes CORS, similar to the middleware
     * implementation in the router. It adds the appropriate CORS headers to
     * the response and handles preflight requests.
     * 
     * @param ctx Router context containing request and response
     * @return true if the request should continue, false for preflight requests
     */
    bool apply(Context& ctx) const {
        const auto& origin = ctx.request.header("Origin");

        // If no Origin header, just continue
        if (origin.empty()) {
            return true;
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
            return true;
        }

        // For preflight requests
        if (ctx.request.method == HTTP_OPTIONS) {
            const auto& request_method = ctx.request.header("Access-Control-Request-Method");
            if (!request_method.empty()) {
                // Add allowed methods
                const auto& allowed_methods = _options->allowed_methods();
                if (!allowed_methods.empty()) {
                    ctx.response.add_header("Access-Control-Allow-Methods",
                                        utility::join(allowed_methods, ", "));
                } else {
                    // Default to common methods if none specified
                    ctx.response.add_header("Access-Control-Allow-Methods",
                                        "GET, POST, PUT, DELETE, HEAD, OPTIONS");
                }

                // Add allowed headers
                const auto& allowed_headers = _options->allowed_headers();
                if (!allowed_headers.empty()) {
                    ctx.response.add_header("Access-Control-Allow-Headers",
                                        utility::join(allowed_headers, ", "));
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

                return false; // Skip the rest of middleware chain for preflight
            }
        }

        // For normal requests, add exposed headers if any
        const auto& exposed_headers = _options->exposed_headers();
        if (!exposed_headers.empty()) {
            ctx.response.add_header("Access-Control-Expose-Headers",
                                utility::join(exposed_headers, ", "));
        }

        // Continue with the request processing
        return true;
    }
    
    /**
     * @brief Create a middleware function for the router
     * @return Middleware function that applies CORS processing
     */
    auto middleware() const {
        return [this](Context& ctx) {
            return apply(ctx);
        };
    }
    
    /**
     * @brief Get a reference to the current CORS options
     * @return Reference to CorsOptions
     */
    const CorsOptions& options() const {
        return *_options;
    }
    
    /**
     * @brief Update CORS options
     * @param options New CORS options
     * @return Reference to this Cors instance
     */
    Cors& update_options(const CorsOptions& options) {
        _options = std::make_shared<CorsOptions>(options);
        return *this;
    }
    
private:
    std::shared_ptr<CorsOptions> _options;
};

/**
 * @brief Create a CORS handler with default options
 * @return Cors instance with default options
 */
template <typename Session, typename String = std::string>
inline auto create_cors() {
    return Cors<Session, String>();
}

/**
 * @brief Create a CORS handler with custom options
 * @param options CORS options to use
 * @return Cors instance with the specified options
 */
template <typename Session, typename String = std::string>
inline auto create_cors(const CorsOptions& options) {
    return Cors<Session, String>(options);
}

/**
 * @brief Create a middleware function that applies CORS processing
 * @param options CORS options to use
 * @return Middleware function
 */
template <typename Session, typename String = std::string>
inline auto cors_middleware(const CorsOptions& options) {
    return Cors<Session, String>(options).middleware();
}

} // namespace qb::http 
/**
 * @file qbm/http/middleware/cors.h
 * @brief Defines the CorsMiddleware class for handling Cross-Origin Resource Sharing (CORS).
 *
 * This file contains the definition of the CorsMiddleware class,
 * which is used to handle CORS requests.
 *
 * @warning IMPORTANT - ReDoS Protection:
 * When using OriginMatchStrategy::Regex, be aware that std::regex can be vulnerable to
 * Regular Expression Denial of Service (ReDoS) attacks with pathological patterns and long inputs.
 * The middleware includes built-in limits to mitigate this risk, but care should be taken
 * when defining custom regex patterns.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <algorithm>
#include <atomic> // std::atomic — one-shot wildcard+credentials warning flag
#include <chrono> // For regex timeout protection
#include <functional>
#include <memory>
#include <regex>
#include <stdexcept>
#include <string>
#include <thread> // For regex timeout
#include <vector>
#include <qb/system/time.h>

#include "../request.h"
#include "../response.h"
#include "../routing/middleware.h"
#include "../types.h"
#include "../utility.h"

namespace qb::http {

/** @brief Security limits for CORS processing to prevent DoS/ReDoS attacks */
namespace cors_security_limits {
/**
 * @brief Maximum origin string length for validation
 * @details Prevents ReDoS attacks with very long origin strings against pathological regex patterns
 * @see RFC 6454 - The Web Origin Concept
 */
constexpr std::size_t MAX_ORIGIN_LENGTH = 2048;

/**
 * @brief Maximum number of regex patterns to prevent compilation overhead
 * @details Limits memory usage and compilation time for regex patterns
 */
constexpr std::size_t MAX_REGEX_PATTERNS = 100;

/**
 * @brief Maximum regex pattern string length
 * @details Prevents memory exhaustion from extremely long regex patterns
 */
constexpr std::size_t MAX_REGEX_PATTERN_LENGTH = 1024;

/**
 * @brief Maximum time allowed for a single regex match operation (milliseconds)
 * @details Prevents ReDoS attacks by limiting regex execution time
 */
constexpr qb::duration MAX_REGEX_EXECUTION_TIME = std::chrono::milliseconds{100}; // 100ms max per match
} // namespace cors_security_limits

/**
 * @brief Helper function to perform regex matching with timeout protection
 * @param origin The origin string to match
 * @param pattern The regex pattern
 * @return true if matches, false otherwise or if the origin exceeds the safety cut-off
 *
 * @note ReDoS mitigation is enforced by bounding the origin length. qb's HTTP stack is
 *       strictly single-threaded per listener (see qb::io::async::listener contract), so
 *       spawning a worker thread via `std::async(std::launch::async)` would both violate
 *       the threading model and — because `std::thread::join()` cannot be hardened against
 *       runaway libstdc++ regex back-tracking — provide no real protection. We instead
 *       reject any origin whose length exceeds the documented maximum, on top of which the
 *       caller MUST keep `std::regex` patterns linear (no unbounded alternation on
 *       repetitions, no nested quantifiers).
 */
[[nodiscard]] bool regex_match_with_timeout(const std::string &origin, const std::regex &pattern,
                                            qb::duration /*timeout*/
                                            = cors_security_limits::MAX_REGEX_EXECUTION_TIME) noexcept;

/**
 * @brief Configuration options for Cross-Origin Resource Sharing (CORS).
 *
 * Provides a fluent API to define allowed origins, methods, headers, credentials policy,
 * and other CORS-related settings.
 */
class CorsOptions {
public:
    /** @brief Defines whether credentials (cookies, authorization headers) are allowed with CORS requests. */
    enum class AllowCredentials {
        No, ///< Do not allow credentials.
        Yes ///< Allow credentials.
    };

    /** @brief Defines the strategy used for matching request origins against the allowed list. */
    enum class OriginMatchStrategy {
        Exact,   ///< Origin strings must match exactly (case-sensitive).
        Regex,   ///< Allowed origins are defined as regular expression patterns.
        Function ///< A custom function is used to determine if an origin is allowed.
    };

    /** @brief Default constructor. Initializes with restrictive defaults (no origins allowed). */
    CorsOptions() = default;

    /**
     * @brief Constructs CorsOptions with an initial list of allowed origins (exact match strategy).
     * @param origins_list A vector of allowed origin strings.
     */
    explicit CorsOptions(std::vector<std::string> origins_list)
        : _origins(std::move(origins_list))
        , _match_strategy(OriginMatchStrategy::Exact) {}

    /**
     * @brief Sets the allowed origins using exact string matching.
     * Special value "*" allows all origins (use with caution, especially with credentials).
     * @param origins_list A vector of origin strings.
     * @return Reference to this CorsOptions instance for chaining.
     */
    CorsOptions &
    origins(std::vector<std::string> origins_list) {
        _origins           = std::move(origins_list);
        _match_strategy    = OriginMatchStrategy::Exact;
        _patterns_compiled = false;   // Invalidate compiled regex patterns if any
        _origin_matcher_fn = nullptr; // Invalidate custom matcher if any
        return *this;
    }

    /**
     * @brief Sets the allowed origins using regular expression patterns.
     * @param patterns A vector of ECMA-/Javascript-style regular expression strings.
     * @return Reference to this CorsOptions instance for chaining.
     */
    CorsOptions &
    origin_patterns(std::vector<std::string> patterns) {
        _origins           = std::move(patterns); // Store patterns in _origins for this strategy
        _match_strategy    = OriginMatchStrategy::Regex;
        _patterns_compiled = false;
        _origin_matcher_fn = nullptr;
        return *this;
    }

    /**
     * @brief Sets a custom function to determine if an origin is allowed.
     * The provided function takes the request's Origin header value and returns true if allowed.
     * @param matcher A function `bool(const std::string& origin)`.
     * @return Reference to this CorsOptions instance for chaining.
     */
    CorsOptions &
    origin_matcher(std::function<bool(const std::string &)> matcher) {
        _origin_matcher_fn = std::move(matcher);
        _match_strategy    = OriginMatchStrategy::Function;
        _origins.clear(); // Clear exact/regex origins as function takes precedence
        _patterns_compiled = false;
        return *this;
    }

    /**
     * @brief Sets the HTTP methods allowed for CORS requests (e.g., "GET", "POST").
     * Used in the `Access-Control-Allow-Methods` header for preflight responses.
     * @param methods_list A vector of HTTP method strings.
     * @return Reference to this CorsOptions instance for chaining.
     */
    CorsOptions &
    methods(std::vector<std::string> methods_list) {
        _methods = std::move(methods_list);
        return *this;
    }

    /** @brief Convenience method to allow all common HTTP methods. */
    CorsOptions &
    all_methods() {
        _methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"};
        return *this;
    }

    /**
     * @brief Sets the request headers allowed for CORS requests (e.g., "Content-Type", "Authorization").
     * Used in the `Access-Control-Allow-Headers` header for preflight responses.
     * @param headers_list A vector of allowed header names.
     * @return Reference to this CorsOptions instance for chaining.
     */
    CorsOptions &
    headers(std::vector<std::string> headers_list) {
        _headers = std::move(headers_list);
        return *this;
    }

    /** @brief Convenience method to allow a common set of request headers. */
    CorsOptions &
    common_headers() {
        _headers = {"Accept",     "Accept-Language", "Content-Language",  "Content-Type",  "Authorization", "X-Requested-With", "Origin", "DNT",
                    "User-Agent", "X-Forwarded-For", "If-Modified-Since", "Cache-Control", "Range"};
        return *this;
    }

    /**
     * @brief Sets the response headers that browsers are allowed to access (e.g., "X-Custom-Header").
     * Used in the `Access-Control-Expose-Headers` header.
     * @param headers_list A vector of header names to expose.
     * @return Reference to this CorsOptions instance for chaining.
     */
    CorsOptions &
    expose_headers(std::vector<std::string> headers_list) {
        // Renamed from expose
        _expose_headers = std::move(headers_list);
        return *this;
    }

    /**
     * @brief Sets whether credentials (cookies, HTTP authentication) are supported on CORS requests.
     * @param allow The credential policy.
     * @return Reference to this CorsOptions instance for chaining.
     */
    CorsOptions &
    credentials(AllowCredentials allow) {
        _credentials = allow;
        return *this;
    }

    /**
     * @brief Sets the maximum duration the results of a preflight request can be cached.
     * Used in the `Access-Control-Max-Age` header (serialized as RFC 7231 integer seconds).
     * @param age Max age as a `qb::duration`.
     * @return Reference to this CorsOptions instance for chaining.
     */
    CorsOptions &
    max_age(qb::duration age) {
        _max_age = static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(age).count());
        return *this;
    }

    /** @brief Creates a permissive CORS configuration, typically for development. Allows all origins, methods, and common headers. */
    static CorsOptions permissive();

    /**
     * @brief Creates a more secure CORS configuration, suitable as a base for production.
     * @param allowed_origins_list A list of specific origins that are allowed.
     * @return CorsOptions with more restrictive settings.
     */
    static CorsOptions secure(const std::vector<std::string> &allowed_origins_list);

    /**
     * @brief Checks if a given origin string is allowed based on the current configuration.
     * @param origin The origin string from the request's Origin header.
     * @return True if the origin is allowed, false otherwise.
     */
    bool is_origin_allowed(const std::string &origin) const;

    /** @brief Checks if the configuration is set to allow all origins explicitly with "*". */
    bool
    should_allow_all_origins_via_wildcard() const {
        // Renamed for clarity
        return _match_strategy == OriginMatchStrategy::Exact && std::find(_origins.begin(), _origins.end(), "*") != _origins.end();
    }

    // Getters with more descriptive names
    [[nodiscard]] const std::vector<std::string> &
    get_origins_list() const {
        return _origins;
    }
    [[nodiscard]] const std::vector<std::string> &
    get_allowed_methods() const {
        return _methods;
    }
    [[nodiscard]] const std::vector<std::string> &
    get_allowed_headers() const {
        return _headers;
    }
    [[nodiscard]] const std::vector<std::string> &
    get_exposed_headers() const {
        return _expose_headers;
    }
    [[nodiscard]] AllowCredentials
    get_allow_credentials() const {
        return _credentials;
    }
    [[nodiscard]] int
    get_max_age() const {
        return _max_age;
    } // Renamed from max_age_val
    [[nodiscard]] OriginMatchStrategy
    get_match_strategy() const {
        return _match_strategy;
    }

private:
    std::vector<std::string>                 _origins;
    std::vector<std::string>                 _methods = {"GET", "HEAD", "POST"}; // Default to common safe methods
    std::vector<std::string>                 _headers; // Empty by default, often specified by Access-Control-Request-Headers
    std::vector<std::string>                 _expose_headers;
    AllowCredentials                         _credentials    = AllowCredentials::No;
    int                                      _max_age        = 86400; // Default: 24 hours
    OriginMatchStrategy                      _match_strategy = OriginMatchStrategy::Exact;
    std::function<bool(const std::string &)> _origin_matcher_fn;
    mutable std::vector<std::regex>          _regex_patterns;
    mutable bool                             _patterns_compiled = false;

    /** @brief Compiles regex patterns from the stored origin strings if the strategy is Regex. Internal use. */
    void ensure_patterns_compiled() const;
};

/**
 * @brief Middleware for handling Cross-Origin Resource Sharing (CORS) requests.
 *
 * This middleware inspects the `Origin` header of incoming requests and adds appropriate
 * `Access-Control-*` headers to the response based on the configured `CorsOptions`.
 * It correctly handles preflight (OPTIONS) requests.
 *
 * @tparam SessionType The type of the session object managed by the router.
 */
template <typename SessionType>
class CorsMiddleware final : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;

    /** @brief Constructs CorsMiddleware with default (permissive) options. */
    CorsMiddleware()
        : _options(std::make_shared<CorsOptions>(CorsOptions::permissive()))
        , _name("CorsMiddleware") {}

    /**
     * @brief Constructs CorsMiddleware with specific options.
     * @param options The CORS configuration to use.
     * @param name An optional name for this middleware instance.
     */
    explicit CorsMiddleware(const CorsOptions &options, std::string name = "CorsMiddleware")
        : _options(std::make_shared<CorsOptions>(options))
        , _name(std::move(name)) {}

    /** @brief Creates a CorsMiddleware instance with permissive options, suitable for development. */
    static std::shared_ptr<CorsMiddleware<SessionType>>
    dev(const std::string &name = "DevCorsMiddleware") {
        return std::make_shared<CorsMiddleware<SessionType>>(CorsOptions::permissive(), name);
    }

    /**
     * @brief Creates a CorsMiddleware instance with secure options, suitable as a base for production.
     * @param allowed_origins_list A list of specific origins that are allowed.
     * @param name An optional name for this middleware instance.
     */
    static std::shared_ptr<CorsMiddleware<SessionType>>
    secure(const std::vector<std::string> &allowed_origins_list, const std::string &name = "SecureCorsMiddleware") {
        return std::make_shared<CorsMiddleware<SessionType>>(CorsOptions::secure(allowed_origins_list), name);
    }

    /**
     * @brief Handles the incoming request, adding CORS headers if applicable.
     * @param ctx The shared context for the current request.
     */
    void
    process(ContextPtr ctx) override {
        const std::string origin = std::string(ctx->request().header("Origin"));

        if (origin.empty()) {
            ctx->complete(AsyncTaskResult::CONTINUE);
            return;
        }

        std::string allow_origin_value;
        bool        origin_is_allowed = _options->is_origin_allowed(origin);

        if (origin_is_allowed) {
            if (_options->should_allow_all_origins_via_wildcard() && _options->get_allow_credentials() != CorsOptions::AllowCredentials::Yes) {
                allow_origin_value = "*";
            } else {
                // Reflect the requesting origin: either it matched a specific rule, or the operator
                // configured '*' together with credentials — where the spec forbids a literal '*'
                // and a concrete origin is the only conformant answer.
                allow_origin_value = origin;

                // Say it out loud, once. `origins({"*"}) + credentials(Yes)` means EVERY site may
                // read this server's authenticated responses: the browser's own safety net (it
                // rejects `Allow-Origin: *` alongside credentials) is precisely what reflecting
                // works around. It is a legitimate explicit choice, but it should never be a silent
                // one — the same treatment pgsql gives `ssl_verify=none`. The default
                // (`CorsOptions::permissive()`) is unaffected: it pairs '*' with credentials(No)
                // and takes the literal-'*' branch above.
                if (_options->should_allow_all_origins_via_wildcard()) {
                    // Atomic, not a plain bool: this runs on every VirtualCore serving CORS, so a
                    // read-modify-write here would be a data race on shared mutable state — the
                    // exact class this codebase audits for. `exchange` also makes it genuinely
                    // once rather than once-per-racing-core.
                    static std::atomic<bool> warned_wildcard_with_credentials{false};
                    if (!warned_wildcard_with_credentials.exchange(true, std::memory_order_relaxed)) {
                        QB_LOG_WARN("[qbm][http][cors] origins(\"*\") combined with credentials(Yes): the requesting Origin is "
                                 "reflected and Access-Control-Allow-Credentials is sent, so ANY site can read authenticated "
                                 "responses from this server. Restrict origins, or set credentials(No).");
                    }
                }
            }
            ctx->response().set_header("Access-Control-Allow-Origin", allow_origin_value);
            if (_options->get_allow_credentials() == CorsOptions::AllowCredentials::Yes) {
                ctx->response().set_header("Access-Control-Allow-Credentials", "true");
            }
        }
        // Always add Vary: Origin if the Origin header was present in the request.
        // This is important for caches to serve correct responses.
        ctx->response().add_header("Vary", "Origin");

        if (!origin_is_allowed) {
            ctx->complete(AsyncTaskResult::CONTINUE); // Origin not allowed, proceed without further CORS headers
            return;
        }

        // Handle Preflight (OPTIONS) request
        if (ctx->request().method() == qb::http::method::OPTIONS) {
            const std::string request_method_header = std::string(ctx->request().header("Access-Control-Request-Method"));
            if (!request_method_header.empty()) {
                // This signifies a preflight request
                ctx->response().add_header("Vary", "Access-Control-Request-Method");

                const auto &allowed_methods_list = _options->get_allowed_methods();
                const bool  method_allowed       = std::find_if(allowed_methods_list.begin(), allowed_methods_list.end(),
                                                                [&](const std::string &configured_method) {
                                                             return utility::iequals(configured_method, request_method_header);
                                                                })
                                                   != allowed_methods_list.end();
                if (!method_allowed) {
                    ctx->response().status() = qb::http::status::FORBIDDEN;
                    ctx->response().body().clear();
                    ctx->complete(AsyncTaskResult::COMPLETE);
                    return;
                }
                ctx->response().set_header("Access-Control-Allow-Methods", utility::join(allowed_methods_list, ", "));

                std::string requested_headers_str             = std::string(ctx->request().header("Access-Control-Request-Headers"));
                const auto &server_configured_allowed_headers = _options->get_allowed_headers();

                if (!requested_headers_str.empty()) {
                    std::vector<std::string> client_requested_list = utility::split_and_trim_header_list(requested_headers_str, ',');
                    std::vector<std::string> approved_for_response;

                    if (!server_configured_allowed_headers.empty()) {
                        for (const auto &req_h : client_requested_list) {
                            auto it = std::find_if(server_configured_allowed_headers.begin(), server_configured_allowed_headers.end(),
                                                   [&](const std::string &configured_h) { return utility::iequals(req_h, configured_h); });
                            if (it != server_configured_allowed_headers.end()) {
                                approved_for_response.push_back(req_h);
                            }
                        }
                    }
                    if (!approved_for_response.empty()) {
                        ctx->response().set_header("Access-Control-Allow-Headers", utility::join(approved_for_response, ", "));
                        ctx->response().add_header("Vary", "Access-Control-Request-Headers");
                    } else {
                        ctx->response().set_header("Access-Control-Allow-Headers", "");
                    }
                } else {
                    if (!server_configured_allowed_headers.empty()) {
                        ctx->response().set_header("Access-Control-Allow-Headers", utility::join(server_configured_allowed_headers, ", "));
                    }
                }

                ctx->response().set_header("Access-Control-Max-Age", std::to_string(_options->get_max_age()));

                ctx->response().status() = qb::http::status::NO_CONTENT;
                ctx->response().body().clear();
                ctx->complete(AsyncTaskResult::COMPLETE); // Crucial: Complete the task here for preflight
                return;                                   // Preflight handled, stop further processing for this request.
            } // End of actual preflight request handling (if Access-Control-Request-Method was present)
        } // End of OPTIONS method check

        // For non-preflight requests (or OPTIONS requests that weren't preflights)
        const auto &exposed_headers_list = _options->get_exposed_headers();
        if (!exposed_headers_list.empty()) {
            ctx->response().set_header("Access-Control-Expose-Headers", utility::join(exposed_headers_list, ", "));
        }

        ctx->complete(AsyncTaskResult::CONTINUE);
    }

    /** @brief Gets the name of this middleware instance. */
    std::string
    name() const override {
        return _name;
    }

    /** @brief Handles cancellation; a no-op for this middleware. */
    void
    cancel() override {
        /* No-op */
    }

    /** @brief Gets the current CORS options. */
    const CorsOptions &
    get_cors_options() const {
        // Renamed from options()
        return *_options;
    }

    /** @brief Updates the CORS options for this middleware instance. */
    CorsMiddleware &
    update_options(const CorsOptions &opts) {
        _options = std::make_shared<CorsOptions>(opts);
        return *this;
    }

private:
    std::shared_ptr<CorsOptions> _options;
    std::string                  _name;
};

// Factory Functions

/**
 * @brief Creates a CorsMiddleware instance.
 * By default, uses permissive options suitable for development.
 * @tparam SessionType The session type.
 * @param options CORS configuration options. Defaults to permissive settings.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created CorsMiddleware.
 */
template <typename SessionType>
std::shared_ptr<CorsMiddleware<SessionType>>
cors_middleware(const CorsOptions &options = CorsOptions::permissive(), const std::string &name = "CorsMiddleware") {
    return std::make_shared<CorsMiddleware<SessionType>>(options, name);
}

/**
 * @brief Creates a CorsMiddleware instance with permissive options, suitable for development.
 * @tparam SessionType The session type.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created CorsMiddleware.
 */
template <typename SessionType>
std::shared_ptr<CorsMiddleware<SessionType>>
cors_dev_middleware(const std::string &name = "DevCorsMiddleware") {
    return CorsMiddleware<SessionType>::dev(name);
}

/**
 * @brief Creates a CorsMiddleware instance with secure options, suitable as a base for production.
 * @tparam SessionType The session type.
 * @param allowed_origins_list A list of specific origins that are allowed.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created CorsMiddleware.
 */
template <typename SessionType>
std::shared_ptr<CorsMiddleware<SessionType>>
cors_secure_middleware(const std::vector<std::string> &allowed_origins_list, const std::string &name = "SecureCorsMiddleware") {
    return CorsMiddleware<SessionType>::secure(allowed_origins_list, name);
}
} // namespace qb::http

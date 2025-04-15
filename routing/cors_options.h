#pragma once

#include <functional>
#include <regex>
#include <string>
#include <vector>

namespace qb::http {

/**
 * @brief CORS options for configuring cross-origin resource sharing
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

private:
    std::vector<std::string>
        _origins; ///< List of allowed origins, "*" means all origins
    std::vector<std::string> _methods;        ///< List of allowed methods
    std::vector<std::string> _headers;        ///< List of allowed headers
    std::vector<std::string> _expose_headers; ///< List of headers to expose
    AllowCredentials         _credentials =
        AllowCredentials::No; ///< Whether to allow credentials
    int _max_age =
        86400; ///< Max age for preflight requests in seconds (default: 24 hours)
    OriginMatchStrategy _match_strategy =
        OriginMatchStrategy::Exact; ///< Origin matching strategy
    std::function<bool(const std::string &)>
        _origin_matcher; ///< Custom origin matcher function

    // Cache for compiled regex patterns (only used with Regex strategy)
    mutable std::vector<std::regex> _regex_patterns;
    mutable bool                    _patterns_compiled = false;

    // Compile regex patterns if needed
    void ensure_patterns_compiled() const;

public:
    /**
     * @brief Default constructor
     */
    CorsOptions();

    /**
     * @brief Constructor with origins
     * @param origins List of allowed origins
     */
    explicit CorsOptions(std::vector<std::string> origins);

    /**
     * @brief Set allowed origins
     * @param origins List of allowed origins
     * @return Reference to this options object
     */
    CorsOptions &origins(std::vector<std::string> origins);

    /**
     * @brief Set regex patterns for allowed origins
     * @param patterns List of regex patterns for allowed origins
     * @return Reference to this options object
     */
    CorsOptions &origin_patterns(std::vector<std::string> patterns);

    /**
     * @brief Set a custom function for origin matching
     * @param matcher Function that takes an origin string and returns true if allowed
     * @return Reference to this options object
     */
    CorsOptions &origin_matcher(std::function<bool(const std::string &)> matcher);

    /**
     * @brief Set allowed methods
     * @param methods List of allowed methods
     * @return Reference to this options object
     */
    CorsOptions &methods(std::vector<std::string> methods);

    /**
     * @brief Enable all common HTTP methods
     * @return Reference to this options object
     */
    CorsOptions &all_methods();

    /**
     * @brief Set allowed headers
     * @param headers List of allowed headers
     * @return Reference to this options object
     */
    CorsOptions &headers(std::vector<std::string> headers);

    /**
     * @brief Enable all commonly used headers
     * @return Reference to this options object
     */
    CorsOptions &common_headers();

    /**
     * @brief Set headers to expose
     * @param headers List of headers to expose
     * @return Reference to this options object
     */
    CorsOptions &expose(std::vector<std::string> headers);

    /**
     * @brief Set whether to allow credentials
     * @param allow Whether to allow credentials
     * @return Reference to this options object
     */
    CorsOptions &credentials(AllowCredentials allow);

    /**
     * @brief Set max age for preflight requests
     * @param age Max age in seconds
     * @return Reference to this options object
     */
    CorsOptions &age(int age);

    /**
     * @brief Create a permissive CORS configuration
     * @return CorsOptions with permissive settings
     */
    static CorsOptions permissive();

    /**
     * @brief Create a secure CORS configuration
     * @param allowed_origins List of specific allowed origins
     * @return CorsOptions with secure settings
     */
    static CorsOptions secure(const std::vector<std::string> &allowed_origins);

    /**
     * @brief Get list of allowed origins
     * @return List of allowed origins
     */
    const std::vector<std::string> &origins() const;

    /**
     * @brief Check if all origins are allowed
     * @return true if all origins are allowed, false otherwise
     */
    bool allow_all_origins() const;

    /**
     * @brief Check if a specific origin is allowed
     * @param origin Origin to check
     * @return true if the origin is allowed, false otherwise
     */
    bool is_origin_allowed(const std::string &origin) const;

    /**
     * @brief Get list of allowed methods
     * @return List of allowed methods
     */
    const std::vector<std::string> &allowed_methods() const;

    /**
     * @brief Get list of allowed headers
     * @return List of allowed headers
     */
    const std::vector<std::string> &allowed_headers() const;

    /**
     * @brief Get list of exposed headers
     * @return List of exposed headers
     */
    const std::vector<std::string> &exposed_headers() const;

    /**
     * @brief Get whether to allow credentials
     * @return Allow credentials setting
     */
    AllowCredentials allow_credentials() const;

    /**
     * @brief Get max age for preflight requests
     * @return Max age in seconds
     */
    int max_age() const;

    /**
     * @brief Get the origin matching strategy
     * @return Origin matching strategy
     */
    OriginMatchStrategy match_strategy() const;
};

} // namespace qb::http
#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <functional>
#include <optional>
#include <qb/json.h>
#include <qb/io/crypto_jwt.h>
#include <vector>

#include "../http.h"
#include "./middleware_interface.h"

// Assuming these are declared globally in the test file and are accessible here
// This is not ideal for library code but necessary for this specific debugging request.
extern std::vector<std::string> adv_test_mw_middleware_execution_log;

namespace qb::http {

/**
 * @brief Token location in requests
 */
enum class JwtTokenLocation {
    HEADER,  ///< In an HTTP header
    COOKIE,  ///< In a cookie
    QUERY    ///< In the URL query parameters
};

/**
 * @brief Options for the JWT middleware
 */
struct JwtOptions {
    std::string secret;            ///< Secret key for JWT validation
    std::string algorithm = "HS256"; ///< Signature algorithm
    bool verify_exp = true;        ///< Verify expiration
    bool verify_nbf = true;        ///< Verify not-before
    bool verify_iat = true;        ///< Verify issued-at
    bool verify_iss = false;       ///< Verify issuer
    bool verify_aud = false;       ///< Verify audience
    bool verify_sub = false;       ///< Verify subject
    std::string issuer;            ///< Expected issuer value
    std::string audience;          ///< Expected audience value
    std::string subject;           ///< Expected subject value
    int leeway = 0;                ///< Clock skew tolerance in seconds
    JwtTokenLocation token_location = JwtTokenLocation::HEADER; ///< Token location
    std::string token_name = "Authorization"; ///< Name of header, cookie or parameter
    std::string auth_scheme = "Bearer"; ///< Authentication scheme for header
};

/**
 * @brief JWT specific errors
 */
enum class JwtError {
    NONE,
    MISSING_TOKEN,
    INVALID_TOKEN,
    TOKEN_EXPIRED,
    TOKEN_NOT_ACTIVE,
    INVALID_SIGNATURE,
    INVALID_CLAIM,
    ALGORITHM_MISMATCH
};

/**
 * @brief JWT error information structure
 */
struct JwtErrorInfo {
    JwtError code;
    std::string message;
};

/**
 * @brief JWT middleware implementing authentication and token validation
 * 
 * This middleware verifies and validates JWT tokens in HTTP requests,
 * with support for different token locations, claim validation,
 * and customization of error responses.
 */
template <typename Session, typename String = std::string>
class JwtMiddleware : public ISyncMiddleware<Session, String> {
public:
    using Context = typename ISyncMiddleware<Session, String>::Context;
    using Validator = std::function<bool(const qb::json&, JwtErrorInfo&)>;
    using ErrorHandler = std::function<void(Context&, const JwtErrorInfo&)>;
    using SuccessHandler = std::function<void(Context&, const qb::json&)>;
    
    /**
     * @brief Constructor with minimal options
     * @param secret Secret key for JWT validation
     * @param algorithm Signature algorithm
     */
    explicit JwtMiddleware(const std::string& secret, const std::string& algorithm = "HS256")
        : _options({secret, algorithm}) {}
    
    /**
     * @brief Constructor with complete options
     * @param options JWT configuration options
     */
    explicit JwtMiddleware(JwtOptions options)
        : _options(std::move(options)) {}
    
    /**
     * @brief Set token location as header
     * @param header_name Header name
     * @param scheme Authentication scheme
     * @return Reference to this middleware for chaining
     */
    JwtMiddleware& from_header(const std::string& header_name, const std::string& scheme = "Bearer") {
        _options.token_location = JwtTokenLocation::HEADER;
        _options.token_name = header_name;
        _options.auth_scheme = scheme;
        return *this;
    }
    
    /**
     * @brief Set token location as cookie
     * @param cookie_name Cookie name
     * @return Reference to this middleware for chaining
     */
    JwtMiddleware& from_cookie(const std::string& cookie_name) {
        _options.token_location = JwtTokenLocation::COOKIE;
        _options.token_name = cookie_name;
        return *this;
    }
    
    /**
     * @brief Set token location as query parameter
     * @param param_name Parameter name
     * @return Reference to this middleware for chaining
     */
    JwtMiddleware& from_query(const std::string& param_name) {
        _options.token_location = JwtTokenLocation::QUERY;
        _options.token_name = param_name;
        return *this;
    }
    
    /**
     * @brief Set required claims
     * @param claims List of required claim names
     * @return Reference to this middleware for chaining
     */
    JwtMiddleware& require_claims(const std::vector<std::string>& claims) {
        _required_claims = claims;
        return *this;
    }
    
    /**
     * @brief Set a custom validator
     * @param validator Validation function
     * @return Reference to this middleware for chaining
     */
    JwtMiddleware& with_validator(Validator validator) {
        _validator = std::move(validator);
        return *this;
    }
    
    /**
     * @brief Set a custom error handler
     * @param handler Error handling function
     * @return Reference to this middleware for chaining
     */
    JwtMiddleware& with_error_handler(ErrorHandler handler) {
        _error_handler = std::move(handler);
        return *this;
    }
    
    /**
     * @brief Set a custom success handler
     * @param handler Success handling function
     * @return Reference to this middleware for chaining
     */
    JwtMiddleware& with_success_handler(SuccessHandler handler) {
        _success_handler = std::move(handler);
        return *this;
    }
    
    /**
     * @brief Set configuration options
     * @param options New options
     * @return Reference to this middleware for chaining
     */
    JwtMiddleware& with_options(const JwtOptions& options) {
        _options = options;
        return *this;
    }
    
    /**
     * @brief Process a request
     * @param ctx Request context
     * @return Middleware result
     */
    MiddlewareResult process(Context& ctx) override {
        if (adv_test_mw_middleware_execution_log.size() < 1000) { 
            adv_test_mw_middleware_execution_log.push_back(name() + " process_start for " + std::string(ctx.request.uri().path()));
        }

        auto token = extract_token(ctx.request);
        if (!token) {
            if (adv_test_mw_middleware_execution_log.size() < 1000) {
                 adv_test_mw_middleware_execution_log.push_back(name() + " stopping: missing token for " + std::string(ctx.request.uri().path()));
            }
            handle_error(ctx, {JwtError::MISSING_TOKEN, "JWT token is missing"});
            return MiddlewareResult::Stop();
        }
        
        JwtErrorInfo error;
        auto payload = verify_token(*token, error);
        if (!payload) {
             if (adv_test_mw_middleware_execution_log.size() < 1000) {
                adv_test_mw_middleware_execution_log.push_back(name() + " stopping: verify_token failed ('" + error.message + "') for " + std::string(ctx.request.uri().path()));
            }
            handle_error(ctx, error);
            return MiddlewareResult::Stop();
        }
        
        for (const auto& claim : _required_claims) {
            if (!payload->contains(claim)) {
                if (adv_test_mw_middleware_execution_log.size() < 1000) {
                    adv_test_mw_middleware_execution_log.push_back(name() + " stopping: missing required claim '" + claim + "' for " + std::string(ctx.request.uri().path()));
                }
                handle_error(ctx, {JwtError::INVALID_CLAIM, "Required claim '" + claim + "' is missing"});
                return MiddlewareResult::Stop();
            }
        }
        
        if (_validator) {
            if (!_validator(*payload, error)) {
                if (adv_test_mw_middleware_execution_log.size() < 1000) {
                    adv_test_mw_middleware_execution_log.push_back(name() + " stopping: custom validator failed ('" + error.message + "') for " + std::string(ctx.request.uri().path()));
                }
                handle_error(ctx, error);
                return MiddlewareResult::Stop();
            }
        }
        
        ctx.template set<qb::json>("jwt_payload", *payload);
        
        if (_success_handler) {
            _success_handler(ctx, *payload);
        }
        
        if (adv_test_mw_middleware_execution_log.size() < 1000) {
            adv_test_mw_middleware_execution_log.push_back(name() + " continuing: token valid for " + std::string(ctx.request.uri().path()));
        }
        return MiddlewareResult::Continue();
    }
    
    /**
     * @brief Get the middleware name
     */
    std::string name() const override {
        return "JwtMiddleware";
    }
    
    /**
     * @brief Create a JWT middleware with a secret key
     * @param secret Secret key
     * @param algorithm Signature algorithm
     * @return Shared JWT middleware
     */
    static std::shared_ptr<JwtMiddleware<Session, String>> create(const std::string& secret, const std::string& algorithm = "HS256") {
        return std::make_shared<JwtMiddleware<Session, String>>(secret, algorithm);
    }
    
    /**
     * @brief Create a JWT middleware with complete options
     * @param options Configuration options
     * @return Shared JWT middleware
     */
    static std::shared_ptr<JwtMiddleware<Session, String>> create_with_options(const JwtOptions& options) {
        return std::make_shared<JwtMiddleware<Session, String>>(options);
    }
    
private:
    JwtOptions _options;
    std::vector<std::string> _required_claims;
    Validator _validator;
    ErrorHandler _error_handler;
    SuccessHandler _success_handler;
    
    /**
     * @brief Extract token from request
     * @param request HTTP request
     * @return Optional JWT token
     */
    std::optional<std::string> extract_token(const TRequest<String>& request) const {
        switch (_options.token_location) {
            case JwtTokenLocation::HEADER: {
                auto header = request.header(_options.token_name);
                if (header.empty()) {
                    return std::nullopt;
                }
                
                if (_options.token_name == "Authorization") {
                    // Handle Authorization header with scheme
                    std::string auth_header = header;
                    if (auth_header.rfind(_options.auth_scheme + " ", 0) != 0) {
                        return std::nullopt;
                    }
                    return auth_header.substr(_options.auth_scheme.length() + 1);
                }
                
                return header;
            }
            
            case JwtTokenLocation::COOKIE: {
                // Use the cookie_value method to retrieve the cookie's value
                auto value = request.cookie_value(_options.token_name);
                if (value.empty()) {
                    return std::nullopt;
                }
                return value;
            }
            
            case JwtTokenLocation::QUERY: {
                // Use the query method to access query parameters
                auto value = request.query(_options.token_name);
                if (value.empty()) {
                    return std::nullopt;
                }
                return value;
            }
        }
        
        return std::nullopt;
    }
    
    /**
     * @brief Verify and decode JWT token
     * @param token JWT token
     * @param error Reference to store errors
     * @return Optional JSON payload
     */
    std::optional<qb::json> verify_token(const std::string& token, JwtErrorInfo& error) const {
        try {
            qb::jwt::VerifyOptions options;
            
            auto jwt_alg_opt = qb::jwt::algorithm_from_string(_options.algorithm);
            if (!jwt_alg_opt) {
                error = {JwtError::ALGORITHM_MISMATCH, "Unsupported algorithm in JwtOptions: " + _options.algorithm};
                if (adv_test_mw_middleware_execution_log.size() < 1000) {
                     adv_test_mw_middleware_execution_log.push_back(name() + " [verify_token] error: " + error.message);
                }
                return std::nullopt;
            }
            options.algorithm = *jwt_alg_opt;
            
            if (options.algorithm == qb::jwt::Algorithm::HS256 ||
                options.algorithm == qb::jwt::Algorithm::HS384 ||
                options.algorithm == qb::jwt::Algorithm::HS512) {
                options.key = _options.secret;
            } else {
            options.key = _options.secret;
            }

            options.verify_expiration = _options.verify_exp;
            options.verify_not_before = _options.verify_nbf;
            options.verify_issuer = _options.verify_iss;
            options.verify_audience = _options.verify_aud;
            options.verify_subject = _options.verify_sub;
            options.clock_skew = std::chrono::seconds(_options.leeway);
            if (_options.verify_iss && !_options.issuer.empty()) {
                options.issuer = _options.issuer;
            }
            if (_options.verify_aud && !_options.audience.empty()) {
                options.audience = _options.audience;
            }
            if (_options.verify_sub && !_options.subject.empty()) {
                options.subject = _options.subject;
            }
            
            auto result = qb::jwt::verify(token, options);
            
            if (!result.is_valid()) {
                switch (result.error) {
                    case qb::jwt::ValidationError::INVALID_FORMAT: error = {JwtError::INVALID_TOKEN, "Invalid token format"}; break;
                    case qb::jwt::ValidationError::INVALID_SIGNATURE: error = {JwtError::INVALID_SIGNATURE, "Invalid signature"}; break;
                    case qb::jwt::ValidationError::TOKEN_EXPIRED: error = {JwtError::TOKEN_EXPIRED, "Token has expired"}; break;
                    case qb::jwt::ValidationError::TOKEN_NOT_ACTIVE: error = {JwtError::TOKEN_NOT_ACTIVE, "Token is not yet active"}; break;
                    case qb::jwt::ValidationError::INVALID_ISSUER: error = {JwtError::INVALID_CLAIM, "Invalid issuer"}; break;
                    case qb::jwt::ValidationError::INVALID_AUDIENCE: error = {JwtError::INVALID_CLAIM, "Invalid audience"}; break;
                    case qb::jwt::ValidationError::INVALID_SUBJECT: error = {JwtError::INVALID_CLAIM, "Invalid subject"}; break;
                    case qb::jwt::ValidationError::CLAIM_MISMATCH: error = {JwtError::INVALID_CLAIM, "Claim validation failed"}; break;
                    default: error = {JwtError::INVALID_TOKEN, "Unknown validation error"};
                }
                return std::nullopt;
            }
            
            qb::json payload_to_return; 
            for (const auto& pair_kv : result.payload) {
                const std::string& key = pair_kv.first;
                const std::string& value_str = pair_kv.second;

                if (key == "roles" || key == "aud") {
                    if (adv_test_mw_middleware_execution_log.size() < 1000) {
                        adv_test_mw_middleware_execution_log.push_back(name() + " [verify_token] attempting to parse value_str for claim '" + key + "': " + value_str);
                    }
                    try {
                        payload_to_return[key] = qb::json::parse(value_str); 
                        if (adv_test_mw_middleware_execution_log.size() < 1000) {
                            adv_test_mw_middleware_execution_log.push_back(name() + " [verify_token] successfully parsed claim '" + key + "'. Resulting type: " + std::string(payload_to_return[key].type_name()));
                        }
                    } catch (const qb::json::exception& e) {
                        if (adv_test_mw_middleware_execution_log.size() < 1000) {
                            adv_test_mw_middleware_execution_log.push_back(name() + " [verify_token] FAILED to parse claim '" + key + "' into JSON object. Error: " + e.what() + ". Storing as string.");
                        }
                        payload_to_return[key] = value_str; 
                    }
                } else {
                    payload_to_return[key] = value_str;
            }
            }
            return payload_to_return;
        }
        catch (const std::exception& e) {
            error = {JwtError::INVALID_TOKEN, std::string("Token validation error: ") + e.what()};
            return std::nullopt;
        }
    }
    
    /**
     * @brief Handle JWT validation error
     * @param ctx Request context
     * @param error Error information
     */
    void handle_error(Context& ctx, const JwtErrorInfo& error) const {
        if (_error_handler) {
            _error_handler(ctx, error);
            return;
        }
        
        // Default error handler
        qb::json response = {
            {"status", "error"},
            {"message", error.message},
            {"code", static_cast<int>(error.code)}
        };
        
        ctx.response.status_code = HTTP_STATUS_UNAUTHORIZED;
        ctx.response.add_header("Content-Type", "application/json");
        ctx.response.body() = response.dump();
        ctx.execute_error_callbacks(error.message);
        ctx.mark_handled();
    }
};

/**
 * @brief Create a JWT middleware as a typed middleware
 * @param secret Secret key
 * @param algorithm Signature algorithm
 * @return Adapted JWT middleware
 */
template <typename Session, typename String = std::string>
auto jwt_middleware(const std::string& secret, const std::string& algorithm = "HS256") {
    auto middleware = std::make_shared<JwtMiddleware<Session, String>>(secret, algorithm);
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create a JWT middleware as a typed middleware with complete options
 * @param options Configuration options
 * @return Adapted JWT middleware
 */
template <typename Session, typename String = std::string>
auto jwt_middleware_with_options(const JwtOptions& options) {
    auto middleware = std::make_shared<JwtMiddleware<Session, String>>(options);
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

} // namespace qb::http 
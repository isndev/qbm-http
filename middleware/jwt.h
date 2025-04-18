#pragma once

#include <qb/json.h>
#include <qb/io/crypto_jwt.h>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "../request.h"
#include "../response.h"
#include "../routing/context.h"

namespace qb::http {

/**
 * @brief Location to extract JWT token from
 */
enum class TokenLocation {
    HEADER,   ///< From Authorization header
    COOKIE,   ///< From cookie
    QUERY     ///< From query parameter
};

/**
 * @brief JWT verification options
 */
struct JwtOptions {
    bool verify_exp = true;      ///< Verify expiration time
    bool verify_nbf = true;      ///< Verify not before time
    bool verify_iat = true;      ///< Verify issued at time
    bool verify_aud = false;     ///< Verify audience
    bool verify_iss = false;     ///< Verify issuer
    bool verify_sub = false;     ///< Verify subject
    std::string audience;        ///< Expected audience value
    std::string issuer;          ///< Expected issuer value
    std::string subject;         ///< Expected subject value
    int leeway = 0;              ///< Leeway in seconds for time validation
};

/**
 * @brief Error codes for JWT validation
 */
enum class JwtError {
    INVALID_TOKEN,
    MISSING_TOKEN,
    TOKEN_EXPIRED,
    TOKEN_NOT_ACTIVE,
    INVALID_SIGNATURE,
    INVALID_CLAIM,
    ALGORITHM_MISMATCH
};

/**
 * @brief JWT validation error information
 */
struct JwtErrorInfo {
    JwtError code;
    std::string message;
};

/**
 * @brief Main JWT middleware class for HTTP authentication
 *
 * This class provides a fluent API for configuring JWT authentication
 * middleware. It supports different token locations, verification options,
 * and custom error handling.
 *
 * @tparam Session HTTP session type
 * @tparam String String type (std::string or std::string_view)
 */
template <typename Session, typename String = std::string>
class JwtMiddleware {
public:
    using Context = RouterContext<Session, String>;
    using ErrorHandler = std::function<void(Context&, const JwtErrorInfo&)>;
    using SuccessHandler = std::function<void(Context&, const qb::json&)>;
    
    /**
     * @brief Default constructor
     */
    JwtMiddleware() = default;
    
    /**
     * @brief Constructor with secret key
     * @param secret Secret key for JWT verification
     */
    explicit JwtMiddleware(const std::string& secret) 
        : _secret(secret), _algorithm("HS256") {}
    
    /**
     * @brief Constructor with public key for RSA/ECDSA
     * @param public_key Public key for JWT verification
     * @param algorithm Algorithm name (RS256, ES256, etc.)
     */
    JwtMiddleware(const std::string& public_key, const std::string& algorithm) 
        : _secret(public_key), _algorithm(algorithm) {}
    
    /**
     * @brief Set the secret key for HMAC algorithms
     * @param secret Secret key
     * @return Reference to this middleware
     */
    JwtMiddleware& with_secret(const std::string& secret) {
        _secret = secret;
        _algorithm = "HS256";
        return *this;
    }
    
    /**
     * @brief Set the public key for RSA/ECDSA algorithms
     * @param public_key Public key
     * @param algorithm Algorithm name (RS256, ES256, etc.)
     * @return Reference to this middleware
     */
    JwtMiddleware& with_public_key(const std::string& public_key, const std::string& algorithm) {
        _secret = public_key;
        _algorithm = algorithm;
        return *this;
    }
    
    /**
     * @brief Set the token location
     * @param location Location to extract token from
     * @param name Name of header/cookie/query parameter
     * @return Reference to this middleware
     */
    JwtMiddleware& from_location(TokenLocation location, const std::string& name) {
        _token_location = location;
        _token_name = name;
        return *this;
    }
    
    /**
     * @brief Extract token from Authorization header
     * @param scheme Auth scheme (default: "Bearer")
     * @return Reference to this middleware
     */
    JwtMiddleware& from_auth_header(const std::string& scheme = "Bearer") {
        _token_location = TokenLocation::HEADER;
        _token_name = "Authorization";
        _auth_scheme = scheme;
        return *this;
    }
    
    /**
     * @brief Extract token from cookie
     * @param cookie_name Cookie name
     * @return Reference to this middleware
     */
    JwtMiddleware& from_cookie(const std::string& cookie_name) {
        _token_location = TokenLocation::COOKIE;
        _token_name = cookie_name;
        return *this;
    }
    
    /**
     * @brief Extract token from query parameter
     * @param param_name Query parameter name
     * @return Reference to this middleware
     */
    JwtMiddleware& from_query(const std::string& param_name) {
        _token_location = TokenLocation::QUERY;
        _token_name = param_name;
        return *this;
    }
    
    /**
     * @brief Configure JWT verification options
     * @param options JWT verification options
     * @return Reference to this middleware
     */
    JwtMiddleware& with_options(const JwtOptions& options) {
        _options = options;
        return *this;
    }
    
    /**
     * @brief Set required claims
     * @param claims List of claim names that must be present
     * @return Reference to this middleware
     */
    JwtMiddleware& require_claims(const std::vector<std::string>& claims) {
        _required_claims = claims;
        return *this;
    }
    
    /**
     * @brief Set error handler
     * @param handler Error handler function
     * @return Reference to this middleware
     */
    JwtMiddleware& with_error_handler(ErrorHandler handler) {
        _error_handler = std::move(handler);
        return *this;
    }
    
    /**
     * @brief Set success handler
     * @param handler Success handler function
     * @return Reference to this middleware
     */
    JwtMiddleware& with_success_handler(SuccessHandler handler) {
        _success_handler = std::move(handler);
        return *this;
    }
    
    /**
     * @brief Set custom token validator
     * @param validator Custom token validator function
     * @return Reference to this middleware
     */
    JwtMiddleware& with_validator(std::function<bool(const qb::json&, JwtErrorInfo&)> validator) {
        _custom_validator = std::move(validator);
        return *this;
    }
    
    /**
     * @brief Create a middleware function for the router
     * @return Middleware function that performs JWT validation
     */
    auto middleware() const {
        return [this](Context& ctx) {
            // Extract token
            auto token = extract_token(ctx.request);
            if (!token) {
                handle_error(ctx, {JwtError::MISSING_TOKEN, "JWT token is missing"});
                return false;
            }
            
            // Verify and decode token
            JwtErrorInfo error;
            auto payload = verify_token(*token, error);
            if (!payload) {
                handle_error(ctx, error);
                return false;
            }
            
            // Check required claims
            for (const auto& claim : _required_claims) {
                if (!payload->contains(claim)) {
                    handle_error(ctx, {JwtError::INVALID_CLAIM, "Required claim '" + claim + "' is missing"});
                    return false;
                }
            }
            
            // Apply custom validator if set
            if (_custom_validator) {
                if (!_custom_validator(*payload, error)) {
                    handle_error(ctx, error);
                    return false;
                }
            }
            
            // Store payload in context
            ctx.template set<qb::json>("jwt_payload", *payload);
            
            // Call success handler if set
            if (_success_handler) {
                _success_handler(ctx, *payload);
            }
            
            return true;
        };
    }
    
private:
    std::string _secret;
    std::string _algorithm = "HS256";
    TokenLocation _token_location = TokenLocation::HEADER;
    std::string _token_name = "Authorization";
    std::string _auth_scheme = "Bearer";
    JwtOptions _options;
    std::vector<std::string> _required_claims;
    ErrorHandler _error_handler;
    SuccessHandler _success_handler;
    std::function<bool(const qb::json&, JwtErrorInfo&)> _custom_validator;
    
    /**
     * @brief Extract token from request based on configured location
     * @param request HTTP request
     * @return Optional containing token if found
     */
    std::optional<std::string> extract_token(const TRequest<String>& request) const {
        switch (_token_location) {
            case TokenLocation::HEADER: {
                auto header = request.header(_token_name);
                if (header.empty()) {
                    return std::nullopt;
                }
                
                if (_token_name == "Authorization") {
                    // Handle Authorization header with scheme
                    std::string auth_header = header;
                    if (auth_header.rfind(_auth_scheme + " ", 0) != 0) {
                        return std::nullopt;
                    }
                    return auth_header.substr(_auth_scheme.length() + 1);
                }
                
                return header;
            }
            
            case TokenLocation::COOKIE: {
                // Use the cookie_value method to retrieve the cookie's value
                auto value = request.cookie_value(_token_name);
                if (value.empty()) {
                    return std::nullopt;
                }
                return value;
            }
            
            case TokenLocation::QUERY: {
                // Use the query method to access query parameters
                auto value = request.query(_token_name);
                if (value.empty()) {
                    return std::nullopt;
                }
                return value;
            }
        }
        
        return std::nullopt;
    }
    
    /**
     * @brief Verify and decode JWT token using qb::jwt
     * @param token JWT token
     * @param error Output parameter for error information
     * @return Optional containing payload if verification succeeds
     */
    std::optional<qb::json> verify_token(const std::string& token, JwtErrorInfo& error) const {
        try {
            // Convert middleware options to qb::jwt verify options
            qb::jwt::VerifyOptions options;
            
            // Set algorithm
            auto jwt_alg = qb::jwt::algorithm_from_string(_algorithm);
            if (!jwt_alg) {
                error = {JwtError::ALGORITHM_MISMATCH, "Unsupported algorithm: " + _algorithm};
                return std::nullopt;
            }
            options.algorithm = *jwt_alg;
            
            // Set key and verification flags
            options.key = _secret;
            options.verify_expiration = _options.verify_exp;
            options.verify_not_before = _options.verify_nbf;
            options.verify_issuer = _options.verify_iss;
            options.verify_audience = _options.verify_aud;
            options.verify_subject = _options.verify_sub;
            options.clock_skew = std::chrono::seconds(_options.leeway);
            
            // Set expected claim values if verification is enabled
            if (_options.verify_iss && !_options.issuer.empty()) {
                options.issuer = _options.issuer;
            }
            
            if (_options.verify_aud && !_options.audience.empty()) {
                options.audience = _options.audience;
            }
            
            if (_options.verify_sub && !_options.subject.empty()) {
                options.subject = _options.subject;
            }
            
            // Verify the token using qb::jwt
            auto result = qb::jwt::verify(token, options);
            
            // Map validation errors
            if (!result.is_valid()) {
                switch (result.error) {
                    case qb::jwt::ValidationError::INVALID_FORMAT:
                        error = {JwtError::INVALID_TOKEN, "Invalid token format"};
                        break;
                    case qb::jwt::ValidationError::INVALID_SIGNATURE:
                        error = {JwtError::INVALID_SIGNATURE, "Invalid signature"};
                        break;
                    case qb::jwt::ValidationError::TOKEN_EXPIRED:
                        error = {JwtError::TOKEN_EXPIRED, "Token has expired"};
                        break;
                    case qb::jwt::ValidationError::TOKEN_NOT_ACTIVE:
                        error = {JwtError::TOKEN_NOT_ACTIVE, "Token is not yet active"};
                        break;
                    case qb::jwt::ValidationError::INVALID_ISSUER:
                        error = {JwtError::INVALID_CLAIM, "Invalid issuer claim"};
                        break;
                    case qb::jwt::ValidationError::INVALID_AUDIENCE:
                        error = {JwtError::INVALID_CLAIM, "Invalid audience claim"};
                        break;
                    case qb::jwt::ValidationError::INVALID_SUBJECT:
                        error = {JwtError::INVALID_CLAIM, "Invalid subject claim"};
                        break;
                    case qb::jwt::ValidationError::CLAIM_MISMATCH:
                        error = {JwtError::INVALID_CLAIM, "Claim mismatch"};
                        break;
                    default:
                        error = {JwtError::INVALID_TOKEN, "Unknown validation error"};
                        break;
                }
                return std::nullopt;
            }
            
            // Convert the payload to qb::json
            qb::json payload;
            for (const auto& [key, value] : result.payload) {
                payload[key] = value;
            }
            
            return payload;
        } catch (const std::exception& e) {
            error = {JwtError::INVALID_TOKEN, e.what()};
            return std::nullopt;
        }
    }
    
    /**
     * @brief Handle validation error
     * @param ctx Router context
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
        ctx.mark_handled();
    }
};

/**
 * @brief Create a JWT middleware with secret key
 * @param secret Secret key
 * @return JwtMiddleware instance
 */
template <typename Session, typename String = std::string>
inline auto jwt_auth(const std::string& secret) {
    return JwtMiddleware<Session, String>(secret);
}

/**
 * @brief Create a JWT middleware with public key
 * @param public_key Public key
 * @param algorithm Algorithm name
 * @return JwtMiddleware instance
 */
template <typename Session, typename String = std::string>
inline auto jwt_auth_rsa(const std::string& public_key, const std::string& algorithm = "RS256") {
    return JwtMiddleware<Session, String>(public_key, algorithm);
}

/**
 * @brief Create a middleware that verifies JWT from Authorization header
 * @param secret Secret key
 * @return Middleware function
 */
template <typename Session, typename String = std::string>
inline auto jwt_middleware(const std::string& secret) {
    return JwtMiddleware<Session, String>(secret).middleware();
}

} // namespace qb::http 
#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <functional>
#include <optional>
#include <vector>
#include <chrono>
#include <algorithm> 
#include <cctype>    

#include <qb/json.h>
#include <qb/io/crypto_jwt.h>

#include "../routing/middleware.h"
#include "../request.h"
#include "../response.h"
#include "../types.h"
#include "../cookie.h"
#include "../utility.h"

namespace qb::http {

/** @brief Specifies where to look for the JWT in an incoming request. */
enum class JwtTokenLocation {
    HEADER,  ///< Token is expected in an HTTP header (e.g., Authorization).
    COOKIE,  ///< Token is expected in an HTTP cookie.
    QUERY    ///< Token is expected in a URL query parameter.
};

/**
 * @brief Configuration options for the JWTMiddleware.
 */
struct JwtOptions {
    std::string secret;            ///< The secret key (for HMAC) or public key (for RSA/ES).
    std::string algorithm = "HS256"; ///< Expected JWT signature algorithm.
    bool verify_exp = true;        ///< If true, verifies 'exp' (expiration time) claim.
    bool verify_nbf = true;        ///< If true, verifies 'nbf' (not before) claim.
    bool verify_iat = true;        ///< If true, verifies 'iat' (issued at) claim.
    bool verify_iss = false;       ///< If true, verifies 'iss' (issuer) claim against `issuer`.
    bool verify_aud = false;       ///< If true, verifies 'aud' (audience) claim against `audience`.
    bool verify_sub = false;       ///< If true, verifies 'sub' (subject) claim against `subject`.
    std::string issuer;            ///< Expected 'iss' claim value if `verify_iss` is true.
    std::string audience;          ///< Expected 'aud' claim value if `verify_aud` is true.
    std::string subject;           ///< Expected 'sub' claim value if `verify_sub` is true.
    int leeway_seconds = 0;        ///< Clock skew tolerance for time-based claims (exp, nbf).
    JwtTokenLocation token_location = JwtTokenLocation::HEADER; ///< Where to find the token.
    std::string token_name = "Authorization"; ///< Name of the header, cookie, or query parameter.
    std::string auth_scheme = "Bearer"; ///< Authentication scheme prefix (e.g., "Bearer") for header tokens.
};

/** @brief Enumerates specific JWT processing errors. */
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

/** @brief Structure to hold JWT error code and a descriptive message. */
struct JwtErrorInfo {
    JwtError code = JwtError::NONE;
    std::string message;
};

/**
 * @brief Middleware for JWT-based authentication.
 * Extracts and verifies JWTs from requests.
 * @tparam SessionType The type of the session object.
 */
template <typename SessionType>
class JwtMiddleware : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;
    /** 
     * @brief Custom payload validation function.
     * @param payload Decoded JSON payload.
     * @param error_info Reference to populate on failure.
     * @return True if valid, false otherwise.
     */
    using Validator = std::function<bool(const qb::json& payload, JwtErrorInfo& error_info)>;
    /** 
     * @brief Custom error handler function.
     * Called on JWT validation failure. Responsible for setting the HTTP response.
     * @param ctx Request context.
     * @param error_info Details of the JWT error.
     */
    using ErrorHandler = std::function<void(ContextPtr ctx, const JwtErrorInfo& error_info)>; 
    /** 
     * @brief Custom success handler function.
     * Called after successful JWT validation.
     * @param ctx Request context.
     * @param payload Decoded JWT payload.
     */
    using SuccessHandler = std::function<void(ContextPtr ctx, const qb::json& payload)>;
    
    /**
     * @brief Constructor with secret and algorithm.
     * @param secret Secret or public key.
     * @param algorithm JWT signing algorithm (default "HS256").
     */
    explicit JwtMiddleware(const std::string& secret, const std::string& algorithm = "HS256")
        : _options({secret, algorithm}) {}
    
    /**
     * @brief Constructor with detailed options.
     * @param options JwtOptions struct.
     */
    explicit JwtMiddleware(JwtOptions options)
        : _options(std::move(options)) {}
    
    /** @brief Configure token extraction from an HTTP header. */
    JwtMiddleware& from_header(const std::string& header_name, const std::string& scheme = "Bearer") {
        _options.token_location = JwtTokenLocation::HEADER;
        _options.token_name = header_name;
        _options.auth_scheme = scheme;
        return *this;
    }
    
    /** @brief Configure token extraction from an HTTP cookie. */
    JwtMiddleware& from_cookie(const std::string& cookie_name) {
        _options.token_location = JwtTokenLocation::COOKIE;
        _options.token_name = cookie_name;
        return *this;
    }
    
    /** @brief Configure token extraction from a URL query parameter. */
    JwtMiddleware& from_query(const std::string& param_name) {
        _options.token_location = JwtTokenLocation::QUERY;
        _options.token_name = param_name;
        return *this;
    }
    
    /** @brief Specify claims that must be present in the JWT payload. */
    JwtMiddleware& require_claims(const std::vector<std::string>& claims) {
        _required_claims = claims;
        return *this;
    }
    
    /** @brief Set a custom validation function for the JWT payload. */
    JwtMiddleware& with_validator(Validator validator_fn) {
        _validator = std::move(validator_fn);
        return *this;
    }
    
    /** @brief Set a custom error handling function. */
    JwtMiddleware& with_error_handler(ErrorHandler handler_fn) {
        _error_handler = std::move(handler_fn);
        return *this;
    }
    
    /** @brief Set a custom success handling function. */
    JwtMiddleware& with_success_handler(SuccessHandler handler_fn) {
        _success_handler = std::move(handler_fn);
        return *this;
    }
    
    /** @brief Override current JWT options. */
    JwtMiddleware& with_options(const JwtOptions& opts) {
        _options = opts;
        return *this;
    }
    
    /**
     * @brief Handles incoming request: extracts, verifies, and validates JWT.
     * @param ctx The request context.
     */
    void process(ContextPtr ctx) override {
        std::optional<std::string> token_opt = extract_token(ctx->request());
        if (!token_opt) {
            handle_error(ctx, {JwtError::MISSING_TOKEN, "JWT token is missing."});
            return; 
        }
        
        JwtErrorInfo error_info{JwtError::NONE, ""};
        std::optional<qb::json> payload_opt = verify_token(*token_opt, error_info);
        if (!payload_opt) {
            handle_error(ctx, error_info);
            return; 
        }
        
        for (const auto& claim_name : _required_claims) {
            if (!payload_opt->contains(claim_name)) {
                handle_error(ctx, {JwtError::INVALID_CLAIM, "Required claim '" + claim_name + "' is missing."});
                return; 
            }
        }
        
        if (_validator) {
            JwtErrorInfo validator_error{JwtError::NONE, ""};
            if (!_validator(*payload_opt, validator_error)) {
                handle_error(ctx, validator_error.code != JwtError::NONE ? validator_error : JwtErrorInfo{JwtError::INVALID_CLAIM, "Custom JWT validation failed."});
                return; 
            }
        }
        
        ctx->template set<qb::json>("jwt_payload", *payload_opt);
        
        if (_success_handler) {
            _success_handler(ctx, *payload_opt);
        }
        
        ctx->complete(AsyncTaskResult::CONTINUE);
    }
    
    std::string name() const override {
        return _name;
    }

    void cancel() override {
        // No-op for this synchronous middleware.
    }
    
    static std::shared_ptr<JwtMiddleware<SessionType>> create(const std::string& secret, const std::string& algorithm = "HS256") {
        return std::make_shared<JwtMiddleware<SessionType>>(JwtOptions{secret, algorithm});
    }
    
    static std::shared_ptr<JwtMiddleware<SessionType>> create_with_options(const JwtOptions& options) {
        return std::make_shared<JwtMiddleware<SessionType>>(options);
    }
    
private:
    JwtOptions _options;
    std::string _name = "JwtMiddleware"; 
    std::vector<std::string> _required_claims;
    Validator _validator;
    ErrorHandler _error_handler;
    SuccessHandler _success_handler;
    
    std::optional<std::string> extract_token(const Request& req) const {
        if (_options.token_location == JwtTokenLocation::HEADER) {
            std::string header_value = req.header(_options.token_name, 0, "");
            if (header_value.empty()) {
                return std::nullopt;
            }

            header_value.erase(0, header_value.find_first_not_of(" \t\n\r\f "));
            header_value.erase(header_value.find_last_not_of(" \t\n\r\f ") + 1);

            if (_options.auth_scheme.empty()) {
                return header_value.empty() ? std::nullopt : std::make_optional(header_value);
            }

            if (header_value.length() > _options.auth_scheme.length() &&
                std::equal(_options.auth_scheme.begin(), _options.auth_scheme.end(),
                           header_value.begin(),
                           [](char a, char b) {
                               return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
                           })) {
                if (header_value[_options.auth_scheme.length()] != ' ') {
                    return std::nullopt; 
                }
                
                std::string_view token_sv = std::string_view(header_value).substr(_options.auth_scheme.length());
                
                size_t first_char = token_sv.find_first_not_of(" \t\n\r\f ");
                if (first_char == std::string_view::npos) { 
                    return std::nullopt;
                }
                token_sv.remove_prefix(first_char);
                
                if (token_sv.empty()) {
                    return std::nullopt;
                }
                return std::string(token_sv);
            }
            return std::nullopt; 
        } else if (_options.token_location == JwtTokenLocation::COOKIE) {
            std::string cookie_val = req.cookie_value(_options.token_name);
            return cookie_val.empty() ? std::nullopt : std::optional<std::string>(cookie_val);
        } else if (_options.token_location == JwtTokenLocation::QUERY) {
            std::string query_val = req.query(_options.token_name);
            return query_val.empty() ? std::nullopt : std::optional<std::string>(query_val);
        }
        return std::nullopt;
    }
    
    std::optional<qb::json> verify_token(const std::string& token, JwtErrorInfo& error_info) const {
        qb::jwt::VerifyOptions jwt_verify_options;
        
        auto alg_opt = qb::jwt::algorithm_from_string(_options.algorithm);
        if (!alg_opt) {
            error_info = {JwtError::ALGORITHM_MISMATCH, "JWT algorithm '" + _options.algorithm + "' is not supported or recognized by the library."};
            return std::nullopt;
        }
        jwt_verify_options.algorithm = *alg_opt;
        jwt_verify_options.key = _options.secret;
        jwt_verify_options.verify_expiration = _options.verify_exp;
        jwt_verify_options.verify_not_before = _options.verify_nbf;
        jwt_verify_options.clock_skew = std::chrono::seconds(_options.leeway_seconds);

        if (_options.verify_iss) {
            jwt_verify_options.verify_issuer = true;
            jwt_verify_options.issuer = _options.issuer;
        }
        if (_options.verify_aud) {
            jwt_verify_options.verify_audience = true;
            jwt_verify_options.audience = _options.audience;
        }
        if (_options.verify_sub) {
            jwt_verify_options.verify_subject = true;
            jwt_verify_options.subject = _options.subject;
        }

        qb::jwt::ValidationResult result = qb::jwt::verify(token, jwt_verify_options);

        if (result.is_valid()) {
            qb::json payload_json = qb::json::object();
            for(const auto& pair : result.payload) {
                if (pair.second == "true") {
                    payload_json[pair.first] = true;
                } else if (pair.second == "false") {
                    payload_json[pair.first] = false;
                } else {
                    try {
                        size_t pos = 0;
                        long double val = std::stold(pair.second, &pos);
                        if (pos == pair.second.length()) { 
                           if (static_cast<long long>(val) == val) { 
                               payload_json[pair.first] = static_cast<long long>(val);
                           } else {
                               payload_json[pair.first] = val;
                           }
                        } else {
                           payload_json[pair.first] = pair.second; 
                        }
                    } catch (const std::invalid_argument&) {
                        payload_json[pair.first] = pair.second; 
                    } catch (const std::out_of_range&) {
                        payload_json[pair.first] = pair.second; 
                    }
                }
            }
            return payload_json;
        } else {
            switch (result.error) {
                case qb::jwt::ValidationError::INVALID_FORMAT:    error_info = {JwtError::INVALID_TOKEN, "Invalid token format."}; break;
                case qb::jwt::ValidationError::INVALID_SIGNATURE: error_info = {JwtError::INVALID_SIGNATURE, "Invalid token signature."}; break;
                case qb::jwt::ValidationError::TOKEN_EXPIRED:     error_info = {JwtError::TOKEN_EXPIRED, "Token has expired."}; break;
                case qb::jwt::ValidationError::TOKEN_NOT_ACTIVE:  error_info = {JwtError::TOKEN_NOT_ACTIVE, "Token is not yet active."}; break;
                case qb::jwt::ValidationError::INVALID_ISSUER:    error_info = {JwtError::INVALID_CLAIM, "Invalid issuer."}; break;
                case qb::jwt::ValidationError::INVALID_AUDIENCE:  error_info = {JwtError::INVALID_CLAIM, "Invalid audience."}; break;
                case qb::jwt::ValidationError::INVALID_SUBJECT:   error_info = {JwtError::INVALID_CLAIM, "Invalid subject."}; break;
                case qb::jwt::ValidationError::CLAIM_MISMATCH:    
                                                                  error_info = {JwtError::INVALID_CLAIM, "A specific claim value mismatch occurred."}; break;
                default: error_info = {JwtError::INVALID_TOKEN, "Unknown JWT validation error."}; break;
            }
            return std::nullopt;
        }
    }
    
    void handle_error(ContextPtr ctx, const JwtErrorInfo& error) const {
        if (_error_handler) {
            _error_handler(ctx, error);
            if (ctx && !ctx->is_completed() && !ctx->is_cancelled()) {
                 ctx->complete(AsyncTaskResult::COMPLETE); 
            }
            return;
        }
        
        qb::json response_body = { {"error", error.message} };
        
        ctx->response().status_code = HTTP_STATUS_UNAUTHORIZED;
        ctx->response().set_header("Content-Type", "application/json");
        ctx->response().body() = response_body.dump();
        ctx->complete(AsyncTaskResult::COMPLETE); 
    }
};

template <typename SessionType>
std::shared_ptr<JwtMiddleware<SessionType>>
jwt_middleware(const std::string& secret, const std::string& algorithm = "HS256") {
    return JwtMiddleware<SessionType>::create(secret, algorithm);
}

template <typename SessionType>
std::shared_ptr<JwtMiddleware<SessionType>>
jwt_middleware_with_options(const JwtOptions& options) {
    return JwtMiddleware<SessionType>::create_with_options(options);
}

} // namespace qb::http 
/**
 * @file recaptcha.h
 * @brief Middleware for verifying Google reCAPTCHA tokens
 *
 * Copyright (c) 2011-2025 qb - isndev (cpp.actor). All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "middleware_interface.h"
#include "../http.h"

namespace qb::http {

/**
 * @brief Configuration options for the reCAPTCHA middleware
 */
class RecaptchaOptions {
public:
    /**
     * @brief Token location in the request
     */
    enum class TokenLocation {
        Header,  ///< In an HTTP header
        Body,    ///< In the request body
        Query    ///< In the URL query parameters
    };

    /**
     * @brief Default constructor
     */
    RecaptchaOptions() = default;

    /**
     * @brief Constructor with secret key
     * @param secret_key Google reCAPTCHA secret key
     */
    explicit RecaptchaOptions(std::string secret_key)
        : _secret_key(std::move(secret_key)) {}

    /**
     * @brief Set the secret key
     * @param key Secret key for reCAPTCHA verification
     * @return Reference to this options object
     */
    RecaptchaOptions& secret_key(const std::string& key) {
        _secret_key = key;
        return *this;
    }

    /**
     * @brief Set the minimum score
     * @param score Minimum acceptable score (0.0 to 1.0)
     * @return Reference to this options object
     */
    RecaptchaOptions& min_score(float score) {
        _min_score = score;
        return *this;
    }

    /**
     * @brief Set the API URL
     * @param url API URL for reCAPTCHA verification
     * @return Reference to this options object
     */
    RecaptchaOptions& api_url(const std::string& url) {
        _api_url = url;
        return *this;
    }

    /**
     * @brief Configure token location in header
     * @param header_name Header name
     * @return Reference to this options object
     */
    RecaptchaOptions& from_header(const std::string& header_name) {
        _token_location = TokenLocation::Header;
        _token_field_name = header_name;
        return *this;
    }

    /**
     * @brief Configure token location in body
     * @param field_name Field name in request body
     * @return Reference to this options object
     */
    RecaptchaOptions& from_body(const std::string& field_name) {
        _token_location = TokenLocation::Body;
        _token_field_name = field_name;
        return *this;
    }

    /**
     * @brief Configure token location in query parameters
     * @param param_name Query parameter name
     * @return Reference to this options object
     */
    RecaptchaOptions& from_query(const std::string& param_name) {
        _token_location = TokenLocation::Query;
        _token_field_name = param_name;
        return *this;
    }

    /**
     * @brief Create a standard reCAPTCHA configuration for v3
     * @param secret_key Google reCAPTCHA secret key
     * @param min_score Minimum acceptable score (default: 0.5)
     * @return RecaptchaOptions with standard settings
     */
    static RecaptchaOptions v3(const std::string& secret_key, float min_score = 0.5f) {
        return RecaptchaOptions(secret_key)
            .min_score(min_score)
            .from_body("g-recaptcha-response");
    }

    /**
     * @brief Create a strict reCAPTCHA configuration for high security
     * @param secret_key Google reCAPTCHA secret key
     * @return RecaptchaOptions with strict settings
     */
    static RecaptchaOptions strict(const std::string& secret_key) {
        return RecaptchaOptions(secret_key)
            .min_score(0.7f)
            .from_header("X-reCAPTCHA-Token");
    }

    // Getters
    const std::string& secret_key() const { return _secret_key; }
    float min_score() const { return _min_score; }
    const std::string& api_url() const { return _api_url; }
    TokenLocation token_location() const { return _token_location; }
    const std::string& token_field_name() const { return _token_field_name; }

private:
    std::string _secret_key;
    float _min_score = 0.5f;
    std::string _api_url = "https://www.google.com/recaptcha/api/siteverify";
    TokenLocation _token_location = TokenLocation::Body;
    std::string _token_field_name = "g-recaptcha-response";
};

/**
 * @brief Result of reCAPTCHA verification
 */
struct RecaptchaResult {
    bool success = false;
    float score = 0.0f;
    std::string action;
    std::string hostname;
    std::string error_codes;
    std::chrono::system_clock::time_point challenge_ts;
};

/**
 * @brief Advanced middleware for Google reCAPTCHA validation
 *
 * This middleware validates reCAPTCHA tokens by:
 * - Extracting tokens from various locations (headers, body, query)
 * - Verifying tokens with Google's API
 * - Filtering requests based on reCAPTCHA scores
 * - Storing verification results for later use
 */
template <typename Session, typename String = std::string>
class RecaptchaMiddleware : public IAsyncMiddleware<Session, String> {
public:
    using Context = typename IAsyncMiddleware<Session, String>::Context;
    using CompletionCallback = typename IAsyncMiddleware<Session, String>::CompletionCallback;
    
    /**
     * @brief Constructor with options
     * @param options reCAPTCHA configuration options
     * @param name Middleware name
     */
    explicit RecaptchaMiddleware(
        const RecaptchaOptions& options,
        std::string name = "RecaptchaMiddleware"
    ) : _options(std::make_shared<RecaptchaOptions>(options)),
        _name(std::move(name)) {
        
        if (_options->secret_key().empty()) {
            throw std::invalid_argument("reCAPTCHA secret key is required");
        }
    }
    
    /**
     * @brief Constructor with secret key and minimum score
     * @param secret_key Google reCAPTCHA secret key
     * @param min_score Minimum acceptable score
     * @param name Middleware name
     */
    RecaptchaMiddleware(
        const std::string& secret_key,
        float min_score = 0.5f,
        std::string name = "RecaptchaMiddleware"
    ) : _options(std::make_shared<RecaptchaOptions>(RecaptchaOptions::v3(secret_key, min_score))),
        _name(std::move(name)) {}
    
    /**
     * @brief Create a standard reCAPTCHA middleware for v3
     * @param secret_key Google reCAPTCHA secret key
     * @param min_score Minimum acceptable score
     * @return RecaptchaMiddleware instance with standard settings
     */
    static RecaptchaMiddleware v3(
        const std::string& secret_key,
        float min_score = 0.5f,
        const std::string& name = "RecaptchaV3Middleware"
    ) {
        return RecaptchaMiddleware(RecaptchaOptions::v3(secret_key, min_score), name);
    }
    
    /**
     * @brief Create a strict reCAPTCHA middleware for high security
     * @param secret_key Google reCAPTCHA secret key
     * @return RecaptchaMiddleware instance with strict settings
     */
    static RecaptchaMiddleware strict(
        const std::string& secret_key,
        const std::string& name = "StrictRecaptchaMiddleware"
    ) {
        return RecaptchaMiddleware(RecaptchaOptions::strict(secret_key), name);
    }
    
    /**
     * @brief Process a request asynchronously
     * @param ctx Request context
     * @param callback Completion callback
     */
    void process_async(Context& ctx, CompletionCallback callback) override {
        // Extract the reCAPTCHA token
        auto token = extract_token(ctx.request);
        
        if (!token) {
            // Token missing, reject the request
            ctx.response.status_code = HTTP_STATUS_BAD_REQUEST;
            ctx.response.body() = R"({"error":"reCAPTCHA token is missing"})";
            ctx.mark_handled();
            callback(MiddlewareResult::Stop());
            return;
        }
        
        // Create the request to Google API
        Request req(_options->api_url());
        req.method = HTTP_POST;
        req.add_header("Content-Type", "application/x-www-form-urlencoded");
        
        // Build the request body
        std::string body = "secret=" + _options->secret_key() + "&response=" + *token;
        req.body() = body;
        
        // Send the request asynchronously
        qb::http::POST(req, [ctx, callback, this](Response response) mutable {
            auto result = parse_recaptcha_response(response);
            
            // Store the result in the context for later use
            ctx.template set<RecaptchaResult>("recaptcha_result", result);
            
            if (!result.success || result.score < _options->min_score()) {
                // Verification failed or score too low
                ctx.response.status_code = HTTP_STATUS_FORBIDDEN;
                ctx.response.body() = qb::json{
                    {"error", "reCAPTCHA verification failed"},
                    {"details", result.error_codes.empty() ? "Score too low" : result.error_codes}
                }.dump();
                ctx.mark_handled();
                callback(MiddlewareResult::Stop());
                return;
            }
            
            // Verification successful, continue the middleware chain
            callback(MiddlewareResult::Continue());
        });
    }
    
    /**
     * @brief Get the middleware name
     */
    std::string name() const override {
        return _name;
    }
    
    /**
     * @brief Get current reCAPTCHA options
     * @return Reference to the reCAPTCHA options
     */
    const RecaptchaOptions& options() const {
        return *_options;
    }
    
    /**
     * @brief Update reCAPTCHA options
     * @param options New reCAPTCHA options
     * @return Reference to this middleware
     */
    RecaptchaMiddleware& update_options(const RecaptchaOptions& options) {
        _options = std::make_shared<RecaptchaOptions>(options);
        return *this;
    }
    
private:
    std::shared_ptr<RecaptchaOptions> _options;
    std::string _name;
    
    /**
     * @brief Extract the reCAPTCHA token from the request
     * @param request HTTP request
     * @return Token string or std::nullopt if not found
     */
    template <typename RequestType>
    std::optional<std::string> extract_token(const RequestType& request) const {
        switch (_options->token_location()) {
            case RecaptchaOptions::TokenLocation::Header:
                if (request.has_header(_options->token_field_name())) {
                    return request.header(_options->token_field_name());
                }
                break;
                
            case RecaptchaOptions::TokenLocation::Body:
                try {
                    if (!request.body().empty()) {
                        auto body = qb::json::parse(request.body());
                        if (body.contains(_options->token_field_name())) {
                            return body[_options->token_field_name()].template get<std::string>();
                        }
                    }
                } catch (...) {
                    // Parsing error, return nullopt
                }
                break;
                
            case RecaptchaOptions::TokenLocation::Query:
                return request.query(_options->token_field_name());
        }
        
        return std::nullopt;
    }
    
    /**
     * @brief Parse the response from Google's reCAPTCHA API
     * @param response HTTP response from Google
     * @return Parsed verification result
     */
    RecaptchaResult parse_recaptcha_response(const Response& response) const {
        RecaptchaResult result;
        
        if (response.status_code != HTTP_STATUS_OK) {
            result.error_codes = "HTTP error: " + std::to_string(response.status_code);
            return result;
        }
        
        try {
            auto json = qb::json::parse(response.body());
            
            // Extract basic fields
            result.success = json.value("success", false);
            
            // If successful, extract additional information
            if (result.success) {
                result.score = json.value("score", 0.0f);
                result.action = json.value("action", "");
                result.hostname = json.value("hostname", "");
                
                // Parse the timestamp
                if (json.contains("challenge_ts")) {
                    // In a real implementation, properly parse the timestamp
                    // For now, just use current time
                    result.challenge_ts = std::chrono::system_clock::now();
                }
            }
            
            // Extract error codes if any
            if (json.contains("error-codes")) {
                const auto& errors = json["error-codes"];
                if (errors.is_array()) {
                    std::string error_concat;
                    for (const auto& err : errors) {
                        if (!error_concat.empty()) error_concat += ", ";
                        error_concat += err.template get<std::string>();
                    }
                    result.error_codes = error_concat;
                }
            }
            
        } catch (const std::exception& e) {
            result.success = false;
            result.error_codes = std::string("JSON parsing error: ") + e.what();
        }
        
        return result;
    }
};

/**
 * @brief Create a reCAPTCHA middleware with custom options
 * @param options reCAPTCHA options to use
 * @param name Middleware name
 * @return reCAPTCHA middleware adapter with the specified options
 */
template <typename Session, typename String = std::string>
auto recaptcha_middleware(
    const RecaptchaOptions& options,
    const std::string& name = "RecaptchaMiddleware"
) {
    auto middleware = std::make_shared<RecaptchaMiddleware<Session, String>>(options, name);
    return std::make_shared<AsyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create a reCAPTCHA middleware with secret key and minimum score
 * @param secret_key Google reCAPTCHA secret key
 * @param min_score Minimum acceptable score
 * @param name Middleware name
 * @return reCAPTCHA middleware adapter
 */
template <typename Session, typename String = std::string>
auto recaptcha_middleware(
    const std::string& secret_key,
    float min_score = 0.5f,
    const std::string& name = "RecaptchaMiddleware"
) {
    auto middleware = std::make_shared<RecaptchaMiddleware<Session, String>>(
        secret_key, min_score, name);
    return std::make_shared<AsyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create a standard reCAPTCHA v3 middleware
 * @param secret_key Google reCAPTCHA secret key
 * @param min_score Minimum acceptable score
 * @param name Middleware name
 * @return reCAPTCHA middleware adapter with standard settings
 */
template <typename Session, typename String = std::string>
auto recaptcha_v3_middleware(
    const std::string& secret_key,
    float min_score = 0.5f,
    const std::string& name = "RecaptchaV3Middleware"
) {
    auto middleware = std::make_shared<RecaptchaMiddleware<Session, String>>(
        RecaptchaOptions::v3(secret_key, min_score), name);
    return std::make_shared<AsyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create a strict reCAPTCHA middleware for high security
 * @param secret_key Google reCAPTCHA secret key
 * @param name Middleware name
 * @return reCAPTCHA middleware adapter with strict settings
 */
template <typename Session, typename String = std::string>
auto recaptcha_strict_middleware(
    const std::string& secret_key,
    const std::string& name = "StrictRecaptchaMiddleware"
) {
    auto middleware = std::make_shared<RecaptchaMiddleware<Session, String>>(
        RecaptchaOptions::strict(secret_key), name);
    return std::make_shared<AsyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

} // namespace qb::http 
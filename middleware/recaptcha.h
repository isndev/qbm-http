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

#include <memory>
#include <string>
#include <string_view> // For TRequest/TResponse header views, though Request/Response types are concrete
#include <functional>
#include <optional>
#include <vector>
#include <chrono>      // For RecaptchaResult challenge_ts

#include <qb/json.h>   // For qb::json

#include "../routing/middleware.h" // IMiddleware, Context, AsyncTaskResult
#include "../http.h"               // For qb::http::REQUEST, qb::http::Request, qb::http::Response, http_status
#include "../io/uri.h"             // For qb::io::uri used in api_req construction

namespace qb::http {

/**
 * @brief Configuration options for the RecaptchaMiddleware.
 *
 * Defines settings such as the reCAPTCHA secret key, minimum acceptable score (for v3),
 * the API endpoint for verification, and how to extract the reCAPTCHA token from requests.
 */
class RecaptchaOptions {
public:
    /** @brief Specifies where the reCAPTCHA token is expected in the incoming HTTP request. */
    enum class TokenLocation {
        Header,  ///< Token is in an HTTP header.
        Body,    ///< Token is in the request body (e.g., JSON or form field).
        Query    ///< Token is in a URL query parameter.
    };

    /** @brief Default constructor. Requires `secret_key` to be set before use. */
    RecaptchaOptions() = default;

    /**
     * @brief Constructs RecaptchaOptions with a secret key.
     * @param secret_key_val The Google reCAPTCHA secret key for your site.
     */
    explicit RecaptchaOptions(std::string secret_key_val)
        : _secret_key(std::move(secret_key_val)) {}

    /** @brief Sets the Google reCAPTCHA secret key. This is mandatory. */
    RecaptchaOptions& secret_key(const std::string& key) {
        _secret_key = key;
        return *this;
    }
    /** @brief Sets the minimum score (0.0 to 1.0) for reCAPTCHA v3 to be considered valid. */
    RecaptchaOptions& min_score(float score_val) {
        _min_score = score_val;
        return *this;
    }
    /** @brief Sets the URL for the Google reCAPTCHA site verification API. */
    RecaptchaOptions& api_url(const std::string& url) {
        _api_url = url;
        return *this;
    }
    /** @brief Configures token extraction from a specified HTTP header. */
    RecaptchaOptions& from_header(const std::string& header_name) {
        _token_location = TokenLocation::Header;
        _token_field_name = header_name;
        return *this;
    }
    /** @brief Configures token extraction from a field in the request body. 
     *  The middleware currently attempts to parse the body as JSON if this location is used.
     */
    RecaptchaOptions& from_body(const std::string& field_name) {
        _token_location = TokenLocation::Body;
        _token_field_name = field_name;
        return *this;
    }
    /** @brief Configures token extraction from a specified URL query parameter. */
    RecaptchaOptions& from_query(const std::string& param_name) {
        _token_location = TokenLocation::Query;
        _token_field_name = param_name;
        return *this;
    }

    /** 
     * @brief Creates a standard RecaptchaOptions configuration for reCAPTCHA v3.
     * @param secret_key_val The Google reCAPTCHA secret key.
     * @param min_score_val Minimum acceptable score (default: 0.5).
     * @return RecaptchaOptions instance configured for v3, expecting token in body field "g-recaptcha-response".
     */
    static RecaptchaOptions v3(const std::string& secret_key_val, float min_score_val = 0.5f) {
        return RecaptchaOptions(secret_key_val)
            .min_score(min_score_val)
            .from_body("g-recaptcha-response"); // Default field name for reCAPTCHA v3
    }
    /** 
     * @brief Creates a RecaptchaOptions configuration typically used with a custom header.
     * Often implies a higher security posture or specific frontend integration.
     * @param secret_key_val The Google reCAPTCHA secret key.
     * @return RecaptchaOptions instance configured for header extraction and a higher min_score.
     */
    static RecaptchaOptions strict(const std::string& secret_key_val) {
        return RecaptchaOptions(secret_key_val)
            .min_score(0.7f) // Example of a stricter score
            .from_header("X-reCAPTCHA-Token");
    }

    // Getters
    [[nodiscard]] const std::string& get_secret_key() const { return _secret_key; } // Renamed
    [[nodiscard]] float get_min_score() const { return _min_score; }           // Renamed
    [[nodiscard]] const std::string& get_api_url() const { return _api_url; }     // Renamed
    [[nodiscard]] TokenLocation get_token_location() const { return _token_location; } //Renamed
    [[nodiscard]] const std::string& get_token_field_name() const { return _token_field_name; } //Renamed

private:
    std::string _secret_key;
    float _min_score = 0.5f; // Default for v3, can be overridden
    std::string _api_url = "https://www.google.com/recaptcha/api/siteverify";
    TokenLocation _token_location = TokenLocation::Body;
    std::string _token_field_name = "g-recaptcha-response"; // Common default
};

/** @brief Holds the result of a reCAPTCHA verification attempt from Google's API. */
struct RecaptchaResult { 
    bool success = false;        ///< Whether Google considered the token valid.
    float score = 0.0f;          ///< reCAPTCHA v3 score (0.0 to 1.0).
    std::string action;          ///< The action name associated with the token (for v3).
    std::string hostname;        ///< The hostname that served the reCAPTCHA.
    std::string error_codes;     ///< Comma-separated list of error codes if success is false.
    std::chrono::system_clock::time_point challenge_ts; ///< Timestamp of the challenge load.
};

/**
 * @brief Middleware for verifying Google reCAPTCHA v2 or v3 tokens.
 *
 * This middleware extracts a reCAPTCHA token from the request (header, body, or query)
 * and sends it to Google's site verification API. Based on the response (success, score),
 * it either allows the request to proceed or rejects it.
 * The verification result is stored in the context variable "recaptcha_result".
 * This is an asynchronous middleware due to the external HTTP call.
 *
 * @tparam SessionType The type of the session object managed by the router.
 */
template <typename SessionType>
class RecaptchaMiddleware : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;
    
    /**
     * @brief Constructs RecaptchaMiddleware with specified options.
     * @param options The reCAPTCHA configuration options.
     * @param name An optional name for this middleware instance.
     * @throws std::invalid_argument if the secret key in options is empty.
     */
    explicit RecaptchaMiddleware(
        const RecaptchaOptions& options,
        std::string name = "RecaptchaMiddleware"
    ) : _options(std::make_shared<RecaptchaOptions>(options)),
        _name(std::move(name)) {
        if (_options->get_secret_key().empty()) {
            throw std::invalid_argument("RecaptchaMiddleware: Secret key in options cannot be empty.");
        }
    }
    
    /**
     * @brief Constructs RecaptchaMiddleware primarily for v3 with a secret key and minimum score.
     * Token is expected in the body field "g-recaptcha-response" by default.
     * @param secret_key The Google reCAPTCHA secret key.
     * @param min_score Minimum acceptable score (0.0 to 1.0). Defaults to 0.5.
     * @param name An optional name for this middleware instance.
     */
    RecaptchaMiddleware(
        const std::string& secret_key,
        float min_score = 0.5f,
        std::string name = "RecaptchaMiddleware"
    ) : _options(std::make_shared<RecaptchaOptions>(RecaptchaOptions::v3(secret_key, min_score))),
        _name(std::move(name)) {}
    
    /** @brief Creates a RecaptchaMiddleware instance configured for v3. */
    static std::shared_ptr<RecaptchaMiddleware<SessionType>> v3(
        const std::string& secret_key,
        float min_score = 0.5f,
        const std::string& name = "RecaptchaV3Middleware"
    ) {
        return std::make_shared<RecaptchaMiddleware<SessionType>>(RecaptchaOptions::v3(secret_key, min_score), name);
    }
    
    /** @brief Creates a RecaptchaMiddleware instance configured for stricter header-based token extraction. */
    static std::shared_ptr<RecaptchaMiddleware<SessionType>> strict(
        const std::string& secret_key,
        const std::string& name = "StrictRecaptchaMiddleware"
    ) {
        return std::make_shared<RecaptchaMiddleware<SessionType>>(RecaptchaOptions::strict(secret_key), name);
    }
    
    /**
     * @brief Handles the incoming request by extracting the reCAPTCHA token, verifying it with Google,
     *        and then deciding whether to continue or complete the request based on the verification result.
     * @param ctx The shared context for the current request.
     */
    void process(ContextPtr ctx) override {
        std::optional<std::string> token_opt = extract_token_from_request(ctx->request());
        
        if (!token_opt) {
            set_error_response(ctx, HTTP_STATUS_BAD_REQUEST, "reCAPTCHA token is missing");
            return;
        }
        
        Request api_req(qb::io::uri(_options->get_api_url()));
        api_req.method = qb::http::method::HTTP_POST;
        api_req.set_header("Content-Type", "application/x-www-form-urlencoded");
        
        std::string request_body_str = "secret=" + _options->get_secret_key() + "&response=" + *token_opt;
        // Optionally, include remoteip: &remoteip=USER_IP_ADDRESS
        // auto client_ip = ctx->request().header("X-Forwarded-For"); // Or other IP source
        // if (!client_ip.empty()) { request_body_str += "&remoteip=" + std::string(client_ip); }
        api_req.body() = request_body_str;
        
        auto shared_ctx = ctx; // Capture context by shared_ptr for async callback
        qb::http::REQUEST(std::move(api_req), // Assuming qb::http::REQUEST is an alias for the async client call
            [shared_ctx, this](qb::http::async::Reply&& api_reply) mutable { 
            RecaptchaResult verification_result = parse_google_recaptcha_response(api_reply.response);
            
            shared_ctx->set<RecaptchaResult>("recaptcha_result", verification_result);
            
            if (!verification_result.success || verification_result.score < _options->get_min_score()) {
                set_error_response(shared_ctx, HTTP_STATUS_FORBIDDEN, 
                                   "reCAPTCHA verification failed", 
                                   verification_result.error_codes.empty() ? "Score too low or invalid token" : verification_result.error_codes);
            } else {
                shared_ctx->complete(AsyncTaskResult::CONTINUE);
            }
        });
    }
    
    /** @brief Gets the name of this middleware instance. */
    std::string name() const override {
        return _name;
    }

    /** 
     * @brief Handles cancellation. 
     * TODO: Implement cancellation of the in-flight HTTP request to Google if `qb::http::REQUEST` supports it.
     */
    void cancel() override {
        // If _http_request_handle is stored from qb::http::REQUEST, attempt to cancel it here.
    }
    
    /** @brief Gets the current reCAPTCHA options used by this middleware. */
    const RecaptchaOptions& get_options() const { // Renamed from options()
        return *_options;
    }
    
    /** @brief Updates the reCAPTCHA options for this middleware instance. */
    RecaptchaMiddleware& update_options(const RecaptchaOptions& opts) {
        if (opts.get_secret_key().empty()) {
            throw std::invalid_argument("RecaptchaMiddleware update_options: Secret key cannot be empty.");
        }
        _options = std::make_shared<RecaptchaOptions>(opts);
        return *this;
    }
    
private:
    std::shared_ptr<RecaptchaOptions> _options;
    std::string _name;
    // std::shared_ptr<SomeCancellableHttpRequestHandle> _http_request_handle; // For cancel()

    /** @brief Extracts the reCAPTCHA token from the HTTP request based on configured options. */
    std::optional<std::string> extract_token_from_request(const qb::http::Request& request) const {
        const std::string& field_name = _options->get_token_field_name();
        switch (_options->get_token_location()) {
            case RecaptchaOptions::TokenLocation::Header:
                {
                    std::string header_val = std::string(request.header(field_name));
                    return header_val.empty() ? std::nullopt : std::optional<std::string>(header_val);
                }
            case RecaptchaOptions::TokenLocation::Body:
                try {
                    if (!request.body().empty()) {
                        auto body_json = qb::json::parse(request.body().as<std::string>());
                        if (body_json.contains(field_name) && body_json[field_name].is_string()) {
                            return body_json[field_name].get<std::string>();
                        }
                        // TODO: Add support for x-www-form-urlencoded body parsing here if needed.
                    }
                } catch (const qb::json::exception& /*e*/) { /* Parsing failed */ }
                break;
            case RecaptchaOptions::TokenLocation::Query:
                {
                    std::string query_val = request.query(field_name);
                    return query_val.empty() ? std::nullopt : std::optional<std::string>(query_val);
                }
        }
        return std::nullopt;
    }
    
    /** @brief Parses the JSON response from Google's reCAPTCHA site verification API. */
    RecaptchaResult parse_google_recaptcha_response(const qb::http::Response& google_response) const {
        RecaptchaResult result;
        if (google_response.status_code != HTTP_STATUS_OK) {
            result.success = false;
            result.error_codes = "Google API HTTP error: " + std::to_string(static_cast<int>(google_response.status_code));
            return result;
        }
        try {
            auto json_body = qb::json::parse(google_response.body().as<std::string>());
            result.success = json_body.value("success", false);
            if (result.success) {
                result.score = json_body.value("score", 0.0f);
                result.action = json_body.value("action", "");
                result.hostname = json_body.value("hostname", "");
                if (json_body.contains("challenge_ts") && json_body["challenge_ts"].is_string()) {
                    // Basic ISO 8601 string to time_point conversion is non-trivial.
                    // For robust parsing, a date/time library or more detailed parsing is needed.
                    // As a placeholder, or if not critical for your use case:
                    result.challenge_ts = std::chrono::system_clock::now(); 
                }
            }
            if (json_body.contains("error-codes") && json_body["error-codes"].is_array()) {
                std::string error_concat;
                for (const auto& err_item : json_body["error-codes"]) {
                    if (err_item.is_string()) {
                        if (!error_concat.empty()) error_concat += ", ";
                        error_concat += err_item.get<std::string>();
                    }
                }
                result.error_codes = error_concat;
            }
        } catch (const qb::json::exception& e) {
            result.success = false;
            result.error_codes = std::string("Google API JSON parsing error: ") + e.what();
        }
        return result;
    }

    /** @brief Sets a standard error response on the context and completes it. */
    void set_error_response(ContextPtr ctx, http_status status, const std::string& error_message, const std::string& details = "") const {
        ctx->response().status_code = status;
        ctx->response().set_header("Content-Type", "application/json");
        qb::json err_body;
        err_body["error"] = error_message;
        if(!details.empty()) {
            err_body["details"] = details;
        }
        ctx->response().body() = err_body.dump();
        ctx->complete(AsyncTaskResult::COMPLETE);
    }
};

// Factory Functions

/**
 * @brief Creates a RecaptchaMiddleware instance with specified options.
 * @tparam SessionType The session type.
 * @param options The reCAPTCHA configuration options.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created RecaptchaMiddleware.
 */
template <typename SessionType>
std::shared_ptr<RecaptchaMiddleware<SessionType>>
recaptcha_middleware(
    const RecaptchaOptions& options,
    const std::string& name = "RecaptchaMiddleware"
) {
    return std::make_shared<RecaptchaMiddleware<SessionType>>(options, name);
}

/**
 * @brief Creates a RecaptchaMiddleware instance, typically for v3, with a secret key and minimum score.
 * @tparam SessionType The session type.
 * @param secret_key The Google reCAPTCHA secret key.
 * @param min_score Minimum acceptable score (0.0 to 1.0). Defaults to 0.5.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created RecaptchaMiddleware.
 */
template <typename SessionType>
std::shared_ptr<RecaptchaMiddleware<SessionType>>
recaptcha_middleware(
    const std::string& secret_key,
    float min_score = 0.5f,
    const std::string& name = "RecaptchaMiddleware"
) {
    // This overload implies v3-like behavior by default due to min_score.
    return std::make_shared<RecaptchaMiddleware<SessionType>>(RecaptchaOptions::v3(secret_key, min_score), name);
}

/**
 * @brief Creates a RecaptchaMiddleware instance configured for reCAPTCHA v3.
 * @tparam SessionType The session type.
 * @param secret_key The Google reCAPTCHA secret key.
 * @param min_score Minimum acceptable score (default: 0.5).
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created RecaptchaMiddleware.
 */
template <typename SessionType>
std::shared_ptr<RecaptchaMiddleware<SessionType>>
recaptcha_v3_middleware(
    const std::string& secret_key,
    float min_score = 0.5f,
    const std::string& name = "RecaptchaV3Middleware"
) {
    return RecaptchaMiddleware<SessionType>::v3(secret_key, min_score, name);
}

/**
 * @brief Creates a RecaptchaMiddleware instance with stricter defaults (e.g., header token, higher score).
 * @tparam SessionType The session type.
 * @param secret_key The Google reCAPTCHA secret key.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created RecaptchaMiddleware.
 */
template <typename SessionType>
std::shared_ptr<RecaptchaMiddleware<SessionType>>
recaptcha_strict_middleware(
    const std::string& secret_key,
    const std::string& name = "StrictRecaptchaMiddleware"
) {
    return RecaptchaMiddleware<SessionType>::strict(secret_key, name);
}

} // namespace qb::http 
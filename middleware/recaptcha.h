/**
 * @file qbm/http/middleware/recaptcha.h
 * @brief Middleware for verifying Google reCAPTCHA v2/v3 tokens.
 *
 * This middleware extracts a reCAPTCHA token from an HTTP request, sends it to Google's
 * site verification API for validation, and then proceeds or rejects the request based
 * on the verification outcome (success status and score for v3). It handles the asynchronous
 * nature of the external API call.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Middleware
 */
#pragma once

#include <memory>       // For std::shared_ptr, std::make_shared
#include <string>       // For std::string
#include <string_view>  // For string_view usage if Request/Response use it internally
#include <functional>   // For std::function (not directly used by this class, but common in middleware)
#include <optional>     // For std::optional
#include <vector>       // For std::vector (not directly used, but often related)
#include <chrono>       // For std::chrono::system_clock
#include <stdexcept>    // For std::invalid_argument
#include <utility>      // For std::move

#include <qb/json.h>    // For qb::json parsing
#include <qb/io/uri.h>  // For qb::io::uri (used in constructing API request)

#include "../routing/middleware.h" // For IMiddleware, Context, AsyncTaskResult
#include "../http.h"               // For qb::http::REQUEST (async client call), Request, Response, qb::http::status


namespace qb::http {
    /**
     * @brief Configuration options for the `RecaptchaMiddleware`.
     *
     * Defines settings such as the reCAPTCHA secret key, minimum acceptable score (for v3),
     * the API endpoint for verification, and how to extract the reCAPTCHA token from requests.
     */
    class RecaptchaOptions {
    public:
        /** @brief Specifies where the reCAPTCHA token is expected in the incoming HTTP request. */
        enum class TokenLocation {
            Header, ///< Token is in an HTTP header (e.g., "X-reCAPTCHA-Token").
            Body, ///< Token is in the request body (e.g., a JSON field like "g-recaptcha-response").
            Query ///< Token is in a URL query parameter (e.g., "recaptcha_token").
        };

        /** @brief Default constructor. Requires `secret_key` to be set before use. */
        RecaptchaOptions() = default;

        /**
         * @brief Constructs `RecaptchaOptions` with a secret key.
         * @param secret_key_val The Google reCAPTCHA secret key for your site. This is mandatory for the middleware to function.
         */
        explicit RecaptchaOptions(std::string secret_key_val)
            : _secret_key(std::move(secret_key_val)) {
        }

        /** 
         * @brief Sets the Google reCAPTCHA secret key.
         * @param key The secret key.
         * @return Reference to this `RecaptchaOptions` instance for chaining.
         */
        RecaptchaOptions &secret_key(std::string key) {
            // Renamed from const std::string& to std::string for move
            _secret_key = std::move(key);
            return *this;
        }

        /** 
         * @brief Sets the minimum score (0.0 to 1.0) for reCAPTCHA v3 to be considered valid.
         * @param score_val The minimum score. For reCAPTCHA v2, this is typically ignored.
         * @return Reference to this `RecaptchaOptions` instance for chaining.
         */
        RecaptchaOptions &min_score(float score_val) noexcept {
            _min_score = score_val;
            return *this;
        }

        /** 
         * @brief Sets the URL for the Google reCAPTCHA site verification API.
         * Defaults to "https://www.google.com/recaptcha/api/siteverify".
         * @param url The API URL.
         * @return Reference to this `RecaptchaOptions` instance for chaining.
         */
        RecaptchaOptions &api_url(std::string url) {
            // Renamed from const std::string&
            _api_url = std::move(url);
            return *this;
        }

        /** 
         * @brief Configures token extraction from a specified HTTP header.
         * @param header_name The name of the header (e.g., "X-reCAPTCHA-Token").
         * @return Reference to this `RecaptchaOptions` instance for chaining.
         */
        RecaptchaOptions &from_header(std::string header_name) {
            // Renamed from const std::string&
            _token_location = TokenLocation::Header;
            _token_field_name = std::move(header_name);
            return *this;
        }

        /** 
         * @brief Configures token extraction from a field in the request body.
         * The middleware currently attempts to parse the body as JSON if this location is used.
         * @param field_name The name of the field in the JSON body (e.g., "g-recaptcha-response").
         * @return Reference to this `RecaptchaOptions` instance for chaining.
         */
        RecaptchaOptions &from_body(std::string field_name) {
            // Renamed from const std::string&
            _token_location = TokenLocation::Body;
            _token_field_name = std::move(field_name);
            return *this;
        }

        /** 
         * @brief Configures token extraction from a specified URL query parameter.
         * @param param_name The name of the query parameter.
         * @return Reference to this `RecaptchaOptions` instance for chaining.
         */
        RecaptchaOptions &from_query(std::string param_name) {
            // Renamed from const std::string&
            _token_location = TokenLocation::Query;
            _token_field_name = std::move(param_name);
            return *this;
        }

        /** 
         * @brief Creates a standard `RecaptchaOptions` configuration for reCAPTCHA v3.
         * @param secret_key_val The Google reCAPTCHA secret key.
         * @param min_score_val Minimum acceptable score (default: 0.5).
         * @return `RecaptchaOptions` instance configured for v3, expecting token in body field "g-recaptcha-response".
         */
        [[nodiscard]] static RecaptchaOptions v3(const std::string &secret_key_val, float min_score_val = 0.5f) {
            return RecaptchaOptions(secret_key_val)
                    .min_score(min_score_val)
                    .from_body("g-recaptcha-response"); // Default field name for reCAPTCHA v3
        }

        /** 
         * @brief Creates a `RecaptchaOptions` configuration typically used with a custom header.
         * Often implies a higher security posture or specific frontend integration.
         * @param secret_key_val The Google reCAPTCHA secret key.
         * @return `RecaptchaOptions` instance configured for header extraction (X-reCAPTCHA-Token) and a higher min_score (0.7).
         */
        [[nodiscard]] static RecaptchaOptions strict(const std::string &secret_key_val) {
            return RecaptchaOptions(secret_key_val)
                    .min_score(0.7f) // Example of a stricter score
                    .from_header("X-reCAPTCHA-Token");
        }

        // --- Getters ---
        [[nodiscard]] const std::string &get_secret_key() const noexcept { return _secret_key; }
        [[nodiscard]] float get_min_score() const noexcept { return _min_score; }
        [[nodiscard]] const std::string &get_api_url() const noexcept { return _api_url; }
        [[nodiscard]] TokenLocation get_token_location() const noexcept { return _token_location; }
        [[nodiscard]] const std::string &get_token_field_name() const noexcept { return _token_field_name; }

    private:
        std::string _secret_key; ///< Google reCAPTCHA secret key.
        float _min_score = 0.5f; ///< Minimum score for v3. Default is 0.5.
        std::string _api_url = "https://www.google.com/recaptcha/api/siteverify"; ///< Google API URL for verification.
        TokenLocation _token_location = TokenLocation::Body; ///< Default location for the token.
        std::string _token_field_name = "g-recaptcha-response"; ///< Default field/header/param name for the token.
    };

    /** @brief Holds the result of a reCAPTCHA verification attempt from Google's API. */
    struct RecaptchaResult {
        bool success = false; ///< Whether Google considered the token valid overall.
        float score = 0.0f; ///< reCAPTCHA v3 score (0.0 to 1.0).
        std::string action; ///< The action name associated with the token (for v3).
        std::string hostname; ///< The hostname that served the reCAPTCHA challenge.
        std::string error_codes;
        ///< Comma-separated list of error codes if success is false (e.g., "missing-input-secret", "invalid-input-response").
        std::chrono::system_clock::time_point challenge_ts;
        ///< Timestamp of the challenge load (when the reCAPTCHA was solved). Populated if available from Google's response.
    };

    /**
     * @brief Middleware for verifying Google reCAPTCHA v2 or v3 tokens.
     *
     * This middleware extracts a reCAPTCHA token from the request (header, body, or query parameter)
     * based on the provided `RecaptchaOptions`. It then sends this token to Google's site verification API
     * for validation. Based on the API's response (specifically the `success` flag and, for v3, the `score`
     * compared against a `min_score` threshold), the middleware either allows the request to proceed
     * by calling `ctx->complete(AsyncTaskResult::CONTINUE)` or rejects it by generating an error response
     * (typically 400 Bad Request or 403 Forbidden) and calling `ctx->complete(AsyncTaskResult::COMPLETE)`.
     *
     * The detailed verification result from Google is stored in the `Context` variable named "recaptcha_result"
     * as a `RecaptchaResult` struct, making it available for downstream handlers or logging.
     *
     * This is an asynchronous middleware because it performs an external HTTP POST request to Google's API.
     *
     * @tparam SessionType The type of the session object managed by the router, used by `Context`.
     */
    template<typename SessionType>
    class RecaptchaMiddleware : public IMiddleware<SessionType> {
    public:
        /** @brief Convenience alias for a shared pointer to the request `Context`. */
        using ContextPtr = std::shared_ptr<Context<SessionType> >;

        /**
         * @brief Constructs `RecaptchaMiddleware` with specified `RecaptchaOptions`.
         * @param options The reCAPTCHA configuration options. The `secret_key` within options must not be empty.
         * @param name An optional name for this middleware instance, for logging or identification.
         * @throws std::invalid_argument if the secret key in `options` is empty.
         */
        explicit RecaptchaMiddleware(
            RecaptchaOptions options, // Pass by value for potential move
            std::string name = "RecaptchaMiddleware"
        ) : _options(std::make_shared<RecaptchaOptions>(std::move(options))),
            _name(std::move(name)) {
            if (_options->get_secret_key().empty()) {
                throw std::invalid_argument("RecaptchaMiddleware: Secret key in options cannot be empty.");
            }
        }

        /**
         * @brief Constructs `RecaptchaMiddleware` configured for reCAPTCHA v3 with essential parameters.
         * By default, expects the token in the request body field named "g-recaptcha-response".
         * @param secret_key The Google reCAPTCHA secret key. Must not be empty.
         * @param min_score Minimum acceptable score for v3 (0.0 to 1.0). Defaults to 0.5.
         * @param name An optional name for this middleware instance.
         * @throws std::invalid_argument if `secret_key` is empty.
         */
        RecaptchaMiddleware(
            const std::string &secret_key,
            float min_score = 0.5f,
            std::string name = "RecaptchaMiddleware"
        ) : _options(std::make_shared<RecaptchaOptions>(RecaptchaOptions::v3(secret_key, min_score))),
            _name(std::move(name)) {
            if (_options->get_secret_key().empty()) {
                // v3 factory also checks, but good to be explicit.
                throw std::invalid_argument("RecaptchaMiddleware: Secret key cannot be empty.");
            }
        }

        /**
         * @brief Factory method to create a `std::shared_ptr` to a `RecaptchaMiddleware` instance configured for v3.
         * @param secret_key The Google reCAPTCHA secret key.
         * @param min_score Minimum acceptable score (default: 0.5).
         * @param name Optional name for the middleware instance.
         * @return A `std::shared_ptr<RecaptchaMiddleware<SessionType>>`.
         */
        [[nodiscard]] static std::shared_ptr<RecaptchaMiddleware<SessionType> > v3(
            const std::string &secret_key,
            float min_score = 0.5f,
            const std::string &name = "RecaptchaV3Middleware"
        ) {
            return std::make_shared<RecaptchaMiddleware<SessionType> >(RecaptchaOptions::v3(secret_key, min_score),
                                                                       name);
        }

        /**
         * @brief Factory method to create a `std::shared_ptr` to a `RecaptchaMiddleware` instance with stricter defaults.
         * Configured for token extraction from "X-reCAPTCHA-Token" header and a min_score of 0.7.
         * @param secret_key The Google reCAPTCHA secret key.
         * @param name Optional name for the middleware instance.
         * @return A `std::shared_ptr<RecaptchaMiddleware<SessionType>>`.
         */
        [[nodiscard]] static std::shared_ptr<RecaptchaMiddleware<SessionType> > strict(
            const std::string &secret_key,
            const std::string &name = "StrictRecaptchaMiddleware"
        ) {
            return std::make_shared<RecaptchaMiddleware<SessionType> >(RecaptchaOptions::strict(secret_key), name);
        }

        /**
         * @brief Processes the incoming request by extracting the reCAPTCHA token, verifying it with Google's API,
         *        and then deciding whether to continue or complete the request based on the verification result.
         * Stores the `RecaptchaResult` in `ctx->set("recaptcha_result", ...)`.
         * This method is asynchronous due to the external HTTP call.
         * @param ctx The shared `Context` for the current request.
         */
        void process(ContextPtr ctx) override {
            std::optional<std::string> token_opt = extract_token_from_request(ctx->request());

            if (!token_opt || token_opt->empty()) {
                set_error_response(ctx, qb::http::status::BAD_REQUEST, "reCAPTCHA token missing or empty");
                return;
            }

            Request api_req(qb::io::uri(_options->get_api_url()));
            api_req.method() = qb::http::method::POST;
            api_req.set_header("Content-Type", "application/x-www-form-urlencoded");

            std::string request_body_str = "secret=" + _options->get_secret_key() + "&response=" + *token_opt;
            // Optionally, include remoteip if available and desired by Google API policies.
            // std::string client_ip = std::string(ctx->request().header("X-Forwarded-For")); 
            // if (!client_ip.empty()) { 
            //    // Take first IP if multiple are present
            //    auto comma_pos = client_ip.find(',');
            //    if (comma_pos != std::string::npos) client_ip = client_ip.substr(0, comma_pos);
            //    request_body_str += "&remoteip=" + qb::io::uri::encode_form_component(client_ip); 
            // }
            api_req.body() = request_body_str;

            auto shared_ctx = ctx; // Capture context by shared_ptr for async callback
            // Using qb::http::request for the async call (assuming it's the correct alias from http.h)
            qb::http::request(std::move(api_req),
                              [shared_ctx, this](qb::http::async::Reply &&api_reply) mutable {
                                  RecaptchaResult verification_result = parse_google_recaptcha_response(
                                      api_reply.response);

                                  shared_ctx->set<RecaptchaResult>("recaptcha_result", verification_result);

                                  if (!verification_result.success || verification_result.score < _options->
                                      get_min_score()) {
                                      std::string error_detail = "Verification failed.";
                                      if (!verification_result.success && !verification_result.error_codes.empty()) {
                                          error_detail += " Errors: " + verification_result.error_codes;
                                      } else if (verification_result.score < _options->get_min_score()) {
                                          error_detail += " Score (" + std::to_string(verification_result.score) +
                                                  ") is below threshold (" + std::to_string(_options->get_min_score()) +
                                                  ").";
                                      }
                                      set_error_response(shared_ctx, qb::http::status::FORBIDDEN,
                                                         "reCAPTCHA challenge failed", error_detail);
                                  } else {
                                      shared_ctx->complete(AsyncTaskResult::CONTINUE);
                                  }
                              }); // Timeout for this external call can be configured if qb::http::request supports it.
        }

        /** @brief Gets the configured name of this middleware instance. */
        [[nodiscard]] std::string name() const noexcept override {
            return _name;
        }

        /** 
         * @brief Handles cancellation of the request processing.
         * @note TODO: Implement cancellation of the in-flight HTTP request to Google if the 
         *        underlying `qb::http::request` mechanism supports cancellation tokens or handles.
         */
        void cancel() noexcept override {
            // If _http_request_handle (a hypothetical handle to the async qb::http::request call)
            // is stored, attempt to cancel it here. Currently, this is a no-op.
        }

        /** @brief Gets a constant reference to the current `RecaptchaOptions` used by this middleware. */
        [[nodiscard]] const RecaptchaOptions &get_options() const noexcept {
            return *_options;
        }

        /**
         * @brief Updates the reCAPTCHA options for this middleware instance.
         * @param opts The new `RecaptchaOptions` to use. Secret key within options must not be empty.
         * @return Reference to this `RecaptchaMiddleware` for chaining.
         * @throws std::invalid_argument if the secret key in new `opts` is empty.
         */
        RecaptchaMiddleware &update_options(RecaptchaOptions opts) {
            // Pass by value for move
            if (opts.get_secret_key().empty()) {
                throw std::invalid_argument(
                    "RecaptchaMiddleware update_options: Secret key in new options cannot be empty.");
            }
            _options = std::make_shared<RecaptchaOptions>(std::move(opts));
            return *this;
        }

    private:
        std::shared_ptr<RecaptchaOptions> _options; ///< Shared pointer to the reCAPTCHA configuration options.
        std::string _name; ///< Name of this middleware instance.
        // std::shared_ptr<SomeCancellableHttpRequestHandle> _http_request_handle; // Example for future cancellation support

        /** 
         * @brief (Internal) Extracts the reCAPTCHA token string from the HTTP request based on configured options.
         * @param request The incoming `qb::http::Request` object.
         * @return An `std::optional<std::string>` containing the token if found, otherwise `std::nullopt`.
         */
        [[nodiscard]] std::optional<std::string> extract_token_from_request(const qb::http::Request &request) const {
            const std::string &field_name = _options->get_token_field_name();
            switch (_options->get_token_location()) {
                case RecaptchaOptions::TokenLocation::Header: {
                    // Assuming TRequest::header returns a type convertible to std::string or std::string_view
                    std::string header_val_str;
                    const auto &header_val_obj = request.header(field_name);
                    // Default value of header() is empty string_type
                    if constexpr (std::is_convertible_v<decltype(header_val_obj), std::string>) {
                        header_val_str = header_val_obj;
                    } else if constexpr (std::is_convertible_v<decltype(header_val_obj), std::string_view>) {
                        header_val_str = std::string(header_val_obj);
                    } else {
                        // Fallback, assumes .data() and .length()
                        header_val_str.assign(header_val_obj.data(), header_val_obj.length());
                    }
                    return header_val_str.empty()
                               ? std::nullopt
                               : std::optional<std::string>(std::move(header_val_str));
                }
                case RecaptchaOptions::TokenLocation::Body:
                    try {
                        if (!request.body().empty()) {
                            // Assuming body is JSON. For form-urlencoded, specific parsing would be needed.
                            auto body_json = qb::json::parse(request.body().as_string_view());
                            if (body_json.is_object() && body_json.contains(field_name) && body_json[field_name].
                                is_string()) {
                                return body_json[field_name].get<std::string>();
                            }
                        }
                    } catch (const qb::json::exception & /*e*/) {
                        // JSON parsing failed or field not found/not string. Return nullopt.
                    }
                    break;
                case RecaptchaOptions::TokenLocation::Query: {
                    // Assuming TRequest::query returns a type convertible to std::string or std::string_view
                    std::string query_val_str;
                    const auto &query_val_obj = request.query(field_name); // Default value is empty string_type
                    if constexpr (std::is_convertible_v<decltype(query_val_obj), std::string>) {
                        query_val_str = query_val_obj;
                    } else if constexpr (std::is_convertible_v<decltype(query_val_obj), std::string_view>) {
                        query_val_str = std::string(query_val_obj);
                    } else {
                        // Fallback
                        query_val_str.assign(query_val_obj.data(), query_val_obj.length());
                    }
                    return query_val_str.empty() ? std::nullopt : std::optional<std::string>(std::move(query_val_str));
                }
            }
            return std::nullopt;
        }

        /** 
         * @brief (Internal) Parses the JSON response from Google's reCAPTCHA site verification API.
         * @param google_response The `qb::http::Response` received from the Google API.
         * @return A `RecaptchaResult` structure populated with data from the API response.
         */
        [[nodiscard]] RecaptchaResult parse_google_recaptcha_response(const qb::http::Response &google_response) const {
            RecaptchaResult result;
            if (google_response.status() != qb::http::status::OK) {
                result.success = false;
                result.error_codes = "Google API HTTP error: " + qb::http::to_string(google_response.status());
                return result;
            }
            try {
                auto json_body = qb::json::parse(google_response.body().as_string_view());
                result.success = json_body.value("success", false);
                if (json_body.contains("score") && json_body["score"].is_number()) {
                    // Score is for v3
                    result.score = json_body["score"].get<float>();
                }
                if (json_body.contains("action") && json_body["action"].is_string()) {
                    // Action is for v3
                    result.action = json_body["action"].get<std::string>();
                }
                if (json_body.contains("hostname") && json_body["hostname"].is_string()) {
                    result.hostname = json_body["hostname"].get<std::string>();
                }
                if (json_body.contains("challenge_ts") && json_body["challenge_ts"].is_string()) {
                    // Basic ISO 8601 string to time_point conversion is non-trivial and platform-dependent.
                    // For now, we don't parse it. A dedicated date/time library would be needed for robust parsing.
                    // Example: result.challenge_ts = parse_iso8601_string(json_body["challenge_ts"].get<std::string>());
                    // Placeholder: use current time if parsing is not implemented.
                    result.challenge_ts = std::chrono::system_clock::now();
                }
                if (json_body.contains("error-codes") && json_body["error-codes"].is_array()) {
                    std::string error_concat;
                    for (const auto &err_item: json_body["error-codes"]) {
                        if (err_item.is_string()) {
                            if (!error_concat.empty()) error_concat += ", ";
                            error_concat += err_item.get<std::string>();
                        }
                    }
                    result.error_codes = error_concat;
                }
            } catch (const qb::json::exception &e) {
                result.success = false;
                result.error_codes = std::string("Google API JSON parsing error: ") + e.what();
            }
            return result;
        }

        /** 
         * @brief (Internal) Sets a standard error response on the context and completes it.
         * @param ctx The request `Context`.
         * @param status The HTTP status code for the error response.
         * @param error_message The main error message.
         * @param details Optional additional details for the error response body.
         */
        void set_error_response(ContextPtr ctx, qb::http::status status, const std::string &error_message,
                                const std::string &details = "") const {
            ctx->response().status() = status;
            ctx->response().set_content_type("application/json; charset=utf-8");
            qb::json err_body;
            err_body["error"] = error_message;
            if (!details.empty()) {
                err_body["details"] = details;
            }
            ctx->response().body() = err_body.dump();
            ctx->complete(AsyncTaskResult::COMPLETE);
        }
    };

    // --- Factory Functions ---

    /**
     * @brief Creates a `std::shared_ptr` to a `RecaptchaMiddleware` instance with specified options.
     * @tparam SessionType The session type used by the HTTP context.
     * @param options The reCAPTCHA configuration options. Passed by value for potential move.
     * @param name An optional name for the middleware instance.
     * @return A `std::shared_ptr<RecaptchaMiddleware<SessionType>>`.
     * @throws std::invalid_argument if secret key in `options` is empty.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<RecaptchaMiddleware<SessionType> >
    recaptcha_middleware(
        RecaptchaOptions options, // Pass by value for potential move
        const std::string &name = "RecaptchaMiddleware"
    ) {
        return std::make_shared<RecaptchaMiddleware<SessionType> >(std::move(options), name);
    }

    /**
     * @brief Creates a `std::shared_ptr` to a `RecaptchaMiddleware` instance, typically for v3, with essential parameters.
     * @tparam SessionType The session type used by the HTTP context.
     * @param secret_key The Google reCAPTCHA secret key. Must not be empty.
     * @param min_score Minimum acceptable score (0.0 to 1.0). Defaults to 0.5.
     * @param name An optional name for the middleware instance.
     * @return A `std::shared_ptr<RecaptchaMiddleware<SessionType>>`.
     * @throws std::invalid_argument if `secret_key` is empty.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<RecaptchaMiddleware<SessionType> >
    recaptcha_middleware(
        const std::string &secret_key,
        float min_score = 0.5f,
        const std::string &name = "RecaptchaMiddleware"
    ) {
        return std::make_shared<RecaptchaMiddleware<SessionType> >(secret_key, min_score, name);
    }

    /**
     * @brief Creates a `std::shared_ptr` to a `RecaptchaMiddleware` instance explicitly configured for reCAPTCHA v3.
     * Uses `RecaptchaOptions::v3` internally.
     * @tparam SessionType The session type used by the HTTP context.
     * @param secret_key The Google reCAPTCHA secret key.
     * @param min_score Minimum acceptable score (default: 0.5).
     * @param name Optional name for the middleware instance.
     * @return A `std::shared_ptr<RecaptchaMiddleware<SessionType>>`.
     * @throws std::invalid_argument if `secret_key` is empty.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<RecaptchaMiddleware<SessionType> >
    recaptcha_v3_middleware(
        const std::string &secret_key,
        float min_score = 0.5f,
        const std::string &name = "RecaptchaV3Middleware"
    ) {
        return RecaptchaMiddleware<SessionType>::v3(secret_key, min_score, name);
    }

    /**
     * @brief Creates a `std::shared_ptr` to a `RecaptchaMiddleware` instance with stricter default settings.
     * Uses `RecaptchaOptions::strict` internally (token from "X-reCAPTCHA-Token" header, higher min_score).
     * @tparam SessionType The session type used by the HTTP context.
     * @param secret_key The Google reCAPTCHA secret key.
     * @param name Optional name for the middleware instance.
     * @return A `std::shared_ptr<RecaptchaMiddleware<SessionType>>`.
     * @throws std::invalid_argument if `secret_key` is empty.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<RecaptchaMiddleware<SessionType> >
    recaptcha_strict_middleware(
        const std::string &secret_key,
        const std::string &name = "StrictRecaptchaMiddleware"
    ) {
        return RecaptchaMiddleware<SessionType>::strict(secret_key, name);
    }
} // namespace qb::http

} // namespace qb::http 

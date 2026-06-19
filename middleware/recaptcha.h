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
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Middleware
 */
#pragma once

#include <chrono>      // For std::chrono::system_clock
#include <functional>  // For std::function (not directly used by this class, but common in middleware)
#include <memory>      // For std::shared_ptr, std::make_shared
#include <optional>    // For std::optional
#include <stdexcept>   // For std::invalid_argument
#include <string>      // For std::string
#include <string_view> // For string_view usage if Request/Response use it internally
#include <utility>     // For std::move
#include <vector>      // For std::vector (not directly used, but often related)

#include <qb/io/uri.h> // For qb::io::uri (used in constructing API request)
#include <qb/json.h>   // For qb::json parsing

#include "../form.h"               // For x-www-form-urlencoded body token extraction
#include "../http.h"               // For qb::http::REQUEST (async client call), Request, Response, qb::http::status
#include "../routing/middleware.h" // For IMiddleware, Context, AsyncTaskResult

namespace qb::http {
namespace detail {
[[nodiscard]] inline std::string
build_recaptcha_verification_body(std::string_view secret, std::string_view response,
                                  std::optional<std::string_view> remote_ip = std::nullopt) {
    std::string request_body = "secret=" + qb::io::uri::encode(secret) + "&response=" + qb::io::uri::encode(response);
    if (remote_ip && !remote_ip->empty()) {
        request_body += "&remoteip=" + qb::io::uri::encode(*remote_ip);
    }
    return request_body;
}
} // namespace detail

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
        Body,   ///< Token is in the request body (e.g., a JSON field like "g-recaptcha-response").
        Query   ///< Token is in a URL query parameter (e.g., "recaptcha_token").
    };

    enum class ChallengeType {
        Auto, ///< Accept v2 scoreless successes and apply score checks when Google returns a v3 score.
        V2,   ///< Accept scoreless v2 successes and ignore score thresholds.
        V3    ///< Require a score and enforce the configured score threshold.
    };

    /** @brief Default constructor. Requires `secret_key` to be set before use. */
    RecaptchaOptions() = default;

    /**
     * @brief Constructs `RecaptchaOptions` with a secret key.
     * @param secret_key_val The Google reCAPTCHA secret key for your site. This is mandatory for the middleware to function.
     */
    explicit RecaptchaOptions(std::string secret_key_val)
        : _secret_key(std::move(secret_key_val)) {}

    /**
     * @brief Sets the Google reCAPTCHA secret key.
     * @param key The secret key.
     * @return Reference to this `RecaptchaOptions` instance for chaining.
     */
    RecaptchaOptions &
    secret_key(std::string key) {
        // Renamed from const std::string& to std::string for move
        _secret_key = std::move(key);
        return *this;
    }

    /**
     * @brief Sets the minimum score (0.0 to 1.0) for reCAPTCHA v3 to be considered valid.
     * @param score_val The minimum score. For reCAPTCHA v2, this is typically ignored.
     * @return Reference to this `RecaptchaOptions` instance for chaining.
     */
    RecaptchaOptions &
    min_score(float score_val) noexcept {
        _min_score = score_val;
        return *this;
    }

    RecaptchaOptions &
    challenge_type(ChallengeType type) noexcept {
        _challenge_type = type;
        return *this;
    }

    /**
     * @brief Sets the URL for the Google reCAPTCHA site verification API.
     * Defaults to "https://www.google.com/recaptcha/api/siteverify".
     * @param url The API URL.
     * @return Reference to this `RecaptchaOptions` instance for chaining.
     */
    RecaptchaOptions &
    api_url(std::string url) {
        // Renamed from const std::string&
        _api_url = std::move(url);
        return *this;
    }

    /**
     * @brief Configures token extraction from a specified HTTP header.
     * @param header_name The name of the header (e.g., "X-reCAPTCHA-Token").
     * @return Reference to this `RecaptchaOptions` instance for chaining.
     */
    RecaptchaOptions &
    from_header(std::string header_name) {
        // Renamed from const std::string&
        _token_location   = TokenLocation::Header;
        _token_field_name = std::move(header_name);
        return *this;
    }

    /**
     * @brief Configures token extraction from a field in the request body.
     * The middleware currently attempts to parse the body as JSON if this location is used.
     * @param field_name The name of the field in the JSON body (e.g., "g-recaptcha-response").
     * @return Reference to this `RecaptchaOptions` instance for chaining.
     */
    RecaptchaOptions &
    from_body(std::string field_name) {
        // Renamed from const std::string&
        _token_location   = TokenLocation::Body;
        _token_field_name = std::move(field_name);
        return *this;
    }

    /**
     * @brief Configures token extraction from a specified URL query parameter.
     * @param param_name The name of the query parameter.
     * @return Reference to this `RecaptchaOptions` instance for chaining.
     */
    RecaptchaOptions &
    from_query(std::string param_name) {
        // Renamed from const std::string&
        _token_location   = TokenLocation::Query;
        _token_field_name = std::move(param_name);
        return *this;
    }

    /**
     * @brief Creates a standard `RecaptchaOptions` configuration for reCAPTCHA v3.
     * @param secret_key_val The Google reCAPTCHA secret key.
     * @param min_score_val Minimum acceptable score (default: 0.5).
     * @return `RecaptchaOptions` instance configured for v3, expecting token in body field "g-recaptcha-response".
     */
    [[nodiscard]] static RecaptchaOptions
    v3(const std::string &secret_key_val, float min_score_val = 0.5f) {
        return RecaptchaOptions(secret_key_val)
            .min_score(min_score_val)
            .challenge_type(ChallengeType::V3)
            .from_body("g-recaptcha-response"); // Default field name for reCAPTCHA v3
    }

    [[nodiscard]] static RecaptchaOptions
    v2(const std::string &secret_key_val) {
        return RecaptchaOptions(secret_key_val).challenge_type(ChallengeType::V2).from_body("g-recaptcha-response");
    }

    /**
     * @brief Creates a `RecaptchaOptions` configuration typically used with a custom header.
     * Often implies a higher security posture or specific frontend integration.
     * @param secret_key_val The Google reCAPTCHA secret key.
     * @return `RecaptchaOptions` instance configured for header extraction (X-reCAPTCHA-Token) and a higher min_score (0.7).
     */
    [[nodiscard]] static RecaptchaOptions
    strict(const std::string &secret_key_val) {
        return RecaptchaOptions(secret_key_val)
            .min_score(0.7f) // Example of a stricter score
            .challenge_type(ChallengeType::V3)
            .from_header("X-reCAPTCHA-Token");
    }

    // --- Getters ---
    [[nodiscard]] const std::string &
    get_secret_key() const noexcept {
        return _secret_key;
    }
    [[nodiscard]] float
    get_min_score() const noexcept {
        return _min_score;
    }
    [[nodiscard]] const std::string &
    get_api_url() const noexcept {
        return _api_url;
    }
    [[nodiscard]] TokenLocation
    get_token_location() const noexcept {
        return _token_location;
    }
    [[nodiscard]] ChallengeType
    get_challenge_type() const noexcept {
        return _challenge_type;
    }
    [[nodiscard]] const std::string &
    get_token_field_name() const noexcept {
        return _token_field_name;
    }

private:
    std::string   _secret_key;                                                           ///< Google reCAPTCHA secret key.
    float         _min_score        = 0.5f;                                              ///< Minimum score for v3. Default is 0.5.
    std::string   _api_url          = "https://www.google.com/recaptcha/api/siteverify"; ///< Google API URL for verification.
    TokenLocation _token_location   = TokenLocation::Body;                               ///< Default location for the token.
    ChallengeType _challenge_type   = ChallengeType::Auto;                               ///< Default supports v2 and v3 response shapes.
    std::string   _token_field_name = "g-recaptcha-response";                            ///< Default field/header/param name for the token.
};

/** @brief Holds the result of a reCAPTCHA verification attempt from Google's API. */
struct RecaptchaResult {
    bool        success   = false; ///< Whether Google considered the token valid overall.
    float       score     = 0.0f;  ///< reCAPTCHA v3 score (0.0 to 1.0).
    bool        has_score = false; ///< Whether Google's response included a score. v2 responses commonly omit it.
    std::string action;            ///< The action name associated with the token (for v3).
    std::string hostname;          ///< The hostname that served the reCAPTCHA challenge.
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
template <typename SessionType>
class RecaptchaMiddleware final : public IMiddleware<SessionType> {
public:
    /** @brief Convenience alias for a shared pointer to the request `Context`. */
    using ContextPtr           = std::shared_ptr<Context<SessionType>>;
    using VerificationCallback = std::function<void(qb::http::async::Reply &&)>;
    using VerificationClient   = std::function<void(qb::http::Request, VerificationCallback)>;

    /**
     * @brief Constructs `RecaptchaMiddleware` with specified `RecaptchaOptions`.
     * @param options The reCAPTCHA configuration options. The `secret_key` within options must not be empty.
     * @param name An optional name for this middleware instance, for logging or identification.
     * @throws std::invalid_argument if the secret key in `options` is empty.
     */
    explicit RecaptchaMiddleware(RecaptchaOptions options, // Pass by value for potential move
                                 std::string      name = "RecaptchaMiddleware")
        : _options(std::make_shared<RecaptchaOptions>(std::move(options)))
        , _name(std::move(name)) {
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
    RecaptchaMiddleware(const std::string &secret_key, float min_score = 0.5f, std::string name = "RecaptchaMiddleware")
        : _options(std::make_shared<RecaptchaOptions>(RecaptchaOptions::v3(secret_key, min_score)))
        , _name(std::move(name)) {
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
    [[nodiscard]] static std::shared_ptr<RecaptchaMiddleware<SessionType>>
    v3(const std::string &secret_key, float min_score = 0.5f, const std::string &name = "RecaptchaV3Middleware") {
        return std::make_shared<RecaptchaMiddleware<SessionType>>(RecaptchaOptions::v3(secret_key, min_score), name);
    }

    /**
     * @brief Factory method to create a `std::shared_ptr` to a `RecaptchaMiddleware` instance with stricter defaults.
     * Configured for token extraction from "X-reCAPTCHA-Token" header and a min_score of 0.7.
     * @param secret_key The Google reCAPTCHA secret key.
     * @param name Optional name for the middleware instance.
     * @return A `std::shared_ptr<RecaptchaMiddleware<SessionType>>`.
     */
    [[nodiscard]] static std::shared_ptr<RecaptchaMiddleware<SessionType>>
    strict(const std::string &secret_key, const std::string &name = "StrictRecaptchaMiddleware") {
        return std::make_shared<RecaptchaMiddleware<SessionType>>(RecaptchaOptions::strict(secret_key), name);
    }

    /**
     * @brief Processes the incoming request by extracting the reCAPTCHA token, verifying it with Google's API,
     *        and then deciding whether to continue or complete the request based on the verification result.
     * Stores the `RecaptchaResult` in `ctx->set("recaptcha_result", ...)`.
     * This method is asynchronous due to the external HTTP call.
     * @param ctx The shared `Context` for the current request.
     */
    void
    process(ContextPtr ctx) override {
        std::optional<std::string> token_opt = extract_token_from_request(ctx->request());

        if (!token_opt || token_opt->empty()) {
            set_error_response(ctx, qb::http::status::BAD_REQUEST, "reCAPTCHA token missing or empty");
            return;
        }

        Request api_req(qb::io::uri(_options->get_api_url()));
        api_req.method() = qb::http::method::POST;
        api_req.set_header("Content-Type", "application/x-www-form-urlencoded");

        std::string request_body_str = detail::build_recaptcha_verification_body(_options->get_secret_key(), *token_opt);
        // Optionally, include remoteip if available and desired by Google API policies.
        // std::string client_ip = std::string(ctx->request().header("X-Forwarded-For"));
        // if (!client_ip.empty()) {
        //    // Take first IP if multiple are present
        //    auto comma_pos = client_ip.find(',');
        //    if (comma_pos != std::string::npos) client_ip = client_ip.substr(0, comma_pos);
        //    request_body_str = detail::build_recaptcha_verification_body(
        //        _options->get_secret_key(), *token_opt, client_ip);
        // }
        api_req.body() = request_body_str;

        auto shared_ctx       = ctx; // Capture context by shared_ptr for async callback
        auto options_snapshot = _options;
        auto completion       = [shared_ctx, options_snapshot](qb::http::async::Reply &&api_reply) mutable {
            // The request may have been cancelled while the outbound verification
            // call was in flight. In that case, do not mutate the response/context.
            if (!shared_ctx || shared_ctx->is_cancelled() || shared_ctx->is_completed()) {
                return;
            }

            RecaptchaResult verification_result = parse_google_recaptcha_response(api_reply.response);

            shared_ctx->template set<RecaptchaResult>("recaptcha_result", verification_result);

            const auto challenge_type         = options_snapshot->get_challenge_type();
            const bool score_required         = challenge_type == RecaptchaOptions::ChallengeType::V3;
            const bool score_enforced         = challenge_type != RecaptchaOptions::ChallengeType::V2 && verification_result.has_score;
            const bool missing_required_score = score_required && !verification_result.has_score;
            const bool score_below_threshold  = score_enforced && verification_result.score < options_snapshot->get_min_score();
            if (!verification_result.success || missing_required_score || score_below_threshold) {
                std::string error_detail = "Verification failed.";
                if (!verification_result.success && !verification_result.error_codes.empty()) {
                    error_detail += " Errors: " + verification_result.error_codes;
                } else if (missing_required_score) {
                    error_detail += " Score is required for reCAPTCHA v3.";
                } else if (score_below_threshold) {
                    error_detail += " Score (" + std::to_string(verification_result.score) + ") is below threshold ("
                                    + std::to_string(options_snapshot->get_min_score()) + ").";
                }
                set_error_response(shared_ctx, qb::http::status::FORBIDDEN, "reCAPTCHA challenge failed", error_detail);
            } else {
                shared_ctx->complete(AsyncTaskResult::CONTINUE);
            }
        };

        if (_verification_client) {
            _verification_client(std::move(api_req), std::move(completion));
        } else {
            qb::http::REQUEST(std::move(api_req), std::move(completion));
        }
    }

    /** @brief Gets the configured name of this middleware instance. */
    [[nodiscard]] std::string
    name() const noexcept override {
        return _name;
    }

    /**
     * @brief Overrides the outbound verification client.
     *
     * This is primarily useful for deterministic tests or for applications that route
     * outbound HTTP through their own service client. If unset, the middleware uses
     * `qb::http::REQUEST`.
     */
    RecaptchaMiddleware &
    verification_client(VerificationClient client) {
        _verification_client = std::move(client);
        return *this;
    }

    /** @brief Handles cancellation of the request processing. */
    void
    cancel() noexcept override {
        // The default qb::http::REQUEST helper is fire-and-callback based and does not
        // expose a cancellation handle. The callback guards `Context::is_cancelled()`.
    }

    /** @brief Gets a constant reference to the current `RecaptchaOptions` used by this middleware. */
    [[nodiscard]] const RecaptchaOptions &
    get_options() const noexcept {
        return *_options;
    }

    /**
     * @brief Updates the reCAPTCHA options for this middleware instance.
     * @param opts The new `RecaptchaOptions` to use. Secret key within options must not be empty.
     * @return Reference to this `RecaptchaMiddleware` for chaining.
     * @throws std::invalid_argument if the secret key in new `opts` is empty.
     */
    RecaptchaMiddleware &
    update_options(RecaptchaOptions opts) {
        // Pass by value for move
        if (opts.get_secret_key().empty()) {
            throw std::invalid_argument("RecaptchaMiddleware update_options: Secret key in new options cannot be empty.");
        }
        _options = std::make_shared<RecaptchaOptions>(std::move(opts));
        return *this;
    }

private:
    std::shared_ptr<RecaptchaOptions> _options; ///< Shared pointer to the reCAPTCHA configuration options.
    std::string                       _name;    ///< Name of this middleware instance.
    VerificationClient                _verification_client;

    /**
     * @brief (Internal) Extracts the reCAPTCHA token string from the HTTP request based on configured options.
     * @param request The incoming `qb::http::Request` object.
     * @return An `std::optional<std::string>` containing the token if found, otherwise `std::nullopt`.
     */
    [[nodiscard]] std::optional<std::string>
    extract_token_from_request(const qb::http::Request &request) const {
        const std::string &field_name = _options->get_token_field_name();
        switch (_options->get_token_location()) {
            case RecaptchaOptions::TokenLocation::Header: {
                const std::string &header_val = request.header(field_name);
                return header_val.empty() ? std::nullopt : std::optional<std::string>(header_val);
            }
            case RecaptchaOptions::TokenLocation::Body:
                try {
                    if (!request.body().empty()) {
                        // JSON APIs commonly send {"g-recaptcha-response":"..."}.
                        auto body_json = qb::json::parse(request.body().template as<std::string_view>());
                        if (body_json.is_object() && body_json.contains(field_name) && body_json[field_name].is_string()) {
                            return body_json[field_name].get<std::string>();
                        }
                    }
                } catch (const qb::json::exception & /*e*/) {
                    // Fall through to HTML form parsing below.
                }
                try {
                    if (!request.body().empty()) {
                        // Browser form submissions usually send application/x-www-form-urlencoded.
                        auto form_body = request.body().template as<Form>();
                        if (auto value = form_body.get_first(field_name); value && !value->empty()) {
                            return value;
                        }
                    }
                } catch (...) {
                    // Malformed/unsupported body format: treat as missing token.
                }
                break;
            case RecaptchaOptions::TokenLocation::Query: {
                const std::string &query_val = request.query(field_name);
                return query_val.empty() ? std::nullopt : std::optional<std::string>(query_val);
            }
        }
        return std::nullopt;
    }

    /**
     * @brief (Internal) Parses the JSON response from Google's reCAPTCHA site verification API.
     * @param google_response The `qb::http::Response` received from the Google API.
     * @return A `RecaptchaResult` structure populated with data from the API response.
     */
    [[nodiscard]] static RecaptchaResult
    parse_google_recaptcha_response(const qb::http::Response &google_response) {
        RecaptchaResult result;
        if (google_response.status() != qb::http::status::OK) {
            result.success     = false;
            result.error_codes = "Google API HTTP error: " + std::to_string(static_cast<int>(google_response.status()));
            return result;
        }
        try {
            auto json_body = qb::json::parse(google_response.body().template as<std::string_view>());
            result.success = json_body.value("success", false);
            if (json_body.contains("score") && json_body["score"].is_number()) {
                // Score is for v3
                result.score     = json_body["score"].get<float>();
                result.has_score = true;
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
                for (const auto &err_item : json_body["error-codes"]) {
                    if (err_item.is_string()) {
                        if (!error_concat.empty())
                            error_concat += ", ";
                        error_concat += err_item.get<std::string>();
                    }
                }
                result.error_codes = error_concat;
            }
        } catch (const qb::json::exception &e) {
            result.success     = false;
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
    static void
    set_error_response(ContextPtr ctx, qb::http::status status, const std::string &error_message, const std::string &details = "") {
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
template <typename SessionType>
[[nodiscard]] std::shared_ptr<RecaptchaMiddleware<SessionType>>
recaptcha_middleware(RecaptchaOptions   options, // Pass by value for potential move
                     const std::string &name = "RecaptchaMiddleware") {
    return std::make_shared<RecaptchaMiddleware<SessionType>>(std::move(options), name);
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
template <typename SessionType>
[[nodiscard]] std::shared_ptr<RecaptchaMiddleware<SessionType>>
recaptcha_middleware(const std::string &secret_key, float min_score = 0.5f, const std::string &name = "RecaptchaMiddleware") {
    return std::make_shared<RecaptchaMiddleware<SessionType>>(secret_key, min_score, name);
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
template <typename SessionType>
[[nodiscard]] std::shared_ptr<RecaptchaMiddleware<SessionType>>
recaptcha_v3_middleware(const std::string &secret_key, float min_score = 0.5f, const std::string &name = "RecaptchaV3Middleware") {
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
template <typename SessionType>
[[nodiscard]] std::shared_ptr<RecaptchaMiddleware<SessionType>>
recaptcha_strict_middleware(const std::string &secret_key, const std::string &name = "StrictRecaptchaMiddleware") {
    return RecaptchaMiddleware<SessionType>::strict(secret_key, name);
}
} // namespace qb::http

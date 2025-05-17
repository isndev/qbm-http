#pragma once

#include <memory>
#include <string>
#include <optional>
#include <vector>
#include <random> // For nonce generation
#include <algorithm> // For nonce generation
#include <sstream> // For nonce generation
#include <iomanip> // For nonce generation
#include <iostream> // For debug logging

#include "../routing/middleware.h"
#include "../response.h"
#include "../types.h" // For HookPoint, AsyncTaskResult

namespace qb::http {

namespace internal {
    // Helper for nonce generation
    static std::string generate_random_nonce(size_t length = 32) {
        // Simple hex representation of random bytes.
        // For production, consider a Base64 encoded result from a cryptographic RNG.
        std::random_device random_device;
        std::mt19937 generator(random_device());
        std::uniform_int_distribution<> distribution(0, 255);
        
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        // Each byte becomes 2 hex characters.
        for (size_t i = 0; i < length / 2; ++i) {
            ss << std::setw(2) << distribution(generator);
        }
        return ss.str();
    }
} // namespace internal

/**
 * @brief Configuration options for SecurityHeadersMiddleware.
 * Allows setting various HTTP security headers.
 */
class SecurityHeadersOptions {
private:
    std::optional<std::string> _hsts_value;
    bool _set_x_content_type_options_nosniff = false;
    std::optional<std::string> _x_frame_options_value;
    std::optional<std::string> _content_security_policy_value;
    std::optional<std::string> _csp_report_only_value;
    std::optional<std::string> _referrer_policy_value;
    std::optional<std::string> _permissions_policy_value;
    std::optional<std::string> _coop_value; // Cross-Origin-Opener-Policy
    std::optional<std::string> _coep_value; // Cross-Origin-Embedder-Policy
    std::optional<std::string> _corp_value; // Cross-Origin-Resource-Policy
    std::optional<std::string> _x_permitted_cross_domain_policies_value;
    bool _enable_csp_nonce = false;

public:
    SecurityHeadersOptions() = default;

    // Fluent Setters
    SecurityHeadersOptions& with_hsts(const std::string& value) {
        _hsts_value = value;
        return *this;
    }
    SecurityHeadersOptions& without_hsts() {
        _hsts_value.reset();
        return *this;
    }

    SecurityHeadersOptions& with_x_content_type_options_nosniff(bool enable = true) {
        _set_x_content_type_options_nosniff = enable;
        return *this;
    }

    SecurityHeadersOptions& with_x_frame_options(const std::string& value) {
        _x_frame_options_value = value;
        return *this;
    }
    SecurityHeadersOptions& without_x_frame_options() {
        _x_frame_options_value.reset();
        return *this;
    }

    SecurityHeadersOptions& with_content_security_policy(const std::string& value) {
        _content_security_policy_value = value;
        return *this;
    }
    SecurityHeadersOptions& without_content_security_policy() {
        _content_security_policy_value.reset();
        return *this;
    }

    SecurityHeadersOptions& with_content_security_policy_report_only(const std::string& value) {
        _csp_report_only_value = value;
        return *this;
    }
    SecurityHeadersOptions& without_content_security_policy_report_only() {
        _csp_report_only_value.reset();
        return *this;
    }
    
    SecurityHeadersOptions& with_referrer_policy(const std::string& value) {
        _referrer_policy_value = value;
        return *this;
    }
    SecurityHeadersOptions& without_referrer_policy() {
        _referrer_policy_value.reset();
        return *this;
    }

    SecurityHeadersOptions& with_permissions_policy(const std::string& value) {
        _permissions_policy_value = value;
        return *this;
    }
    SecurityHeadersOptions& without_permissions_policy() {
        _permissions_policy_value.reset();
        return *this;
    }

    SecurityHeadersOptions& with_cross_origin_opener_policy(const std::string& value) {
        _coop_value = value;
        return *this;
    }
    SecurityHeadersOptions& without_cross_origin_opener_policy() {
        _coop_value.reset();
        return *this;
    }

    SecurityHeadersOptions& with_cross_origin_embedder_policy(const std::string& value) {
        _coep_value = value;
        return *this;
    }
    SecurityHeadersOptions& without_cross_origin_embedder_policy() {
        _coep_value.reset();
        return *this;
    }

    SecurityHeadersOptions& with_cross_origin_resource_policy(const std::string& value) {
        _corp_value = value;
        return *this;
    }
    SecurityHeadersOptions& without_cross_origin_resource_policy() {
        _corp_value.reset();
        return *this;
    }
    
    SecurityHeadersOptions& with_x_permitted_cross_domain_policies(const std::string& value) {
        _x_permitted_cross_domain_policies_value = value;
        return *this;
    }
    SecurityHeadersOptions& without_x_permitted_cross_domain_policies() {
        _x_permitted_cross_domain_policies_value.reset();
        return *this;
    }

    SecurityHeadersOptions& with_csp_nonce(bool enable = true) {
        _enable_csp_nonce = enable;
        return *this;
    }

    // Getters
    [[nodiscard]] const std::optional<std::string>& get_hsts_value() const { return _hsts_value; }
    [[nodiscard]] bool get_set_x_content_type_options_nosniff() const { return _set_x_content_type_options_nosniff; }
    [[nodiscard]] const std::optional<std::string>& get_x_frame_options_value() const { return _x_frame_options_value; }
    [[nodiscard]] const std::optional<std::string>& get_content_security_policy_value() const { return _content_security_policy_value; }
    [[nodiscard]] const std::optional<std::string>& get_csp_report_only_value() const { return _csp_report_only_value; }
    [[nodiscard]] const std::optional<std::string>& get_referrer_policy_value() const { return _referrer_policy_value; }
    [[nodiscard]] const std::optional<std::string>& get_permissions_policy_value() const { return _permissions_policy_value; }
    [[nodiscard]] const std::optional<std::string>& get_coop_value() const { return _coop_value; }
    [[nodiscard]] const std::optional<std::string>& get_coep_value() const { return _coep_value; }
    [[nodiscard]] const std::optional<std::string>& get_corp_value() const { return _corp_value; }
    [[nodiscard]] const std::optional<std::string>& get_x_permitted_cross_domain_policies_value() const { return _x_permitted_cross_domain_policies_value; }
    [[nodiscard]] bool get_csp_nonce_enabled() const { return _enable_csp_nonce; }

    /**
     * @brief Provides a set of secure default header values.
     * These defaults are generally recommended for enhancing security.
     */
    static SecurityHeadersOptions secure_defaults() {
        SecurityHeadersOptions opts;
        opts._hsts_value = "max-age=31536000; includeSubDomains"; // 1 year
        opts._set_x_content_type_options_nosniff = true;
        opts._x_frame_options_value = "SAMEORIGIN";
        opts._content_security_policy_value = "default-src 'self';object-src 'none';frame-ancestors 'self';base-uri 'self';form-action 'self';";
        opts._referrer_policy_value = "strict-origin-when-cross-origin";
        opts._coop_value = "same-origin";
        // COEP can break sites if not carefully configured with cross-origin resources, so not enabled by default here.
        // opts._coep_value = "require-corp"; 
        opts._x_permitted_cross_domain_policies_value = "none";
        // Permissions-Policy is complex and highly application-specific, so no default value is set.
        return opts;
    }
};

/**
 * @brief Middleware to automatically add various HTTP security headers to responses.
 * @tparam SessionType The type of the session object managed by the router.
 */
template <typename SessionType>
class SecurityHeadersMiddleware : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;

    explicit SecurityHeadersMiddleware(
        SecurityHeadersOptions options = SecurityHeadersOptions::secure_defaults(),
        std::string name = "SecurityHeadersMiddleware"
    ) : _options(std::make_shared<SecurityHeadersOptions>(std::move(options))),
        _name(std::move(name)) {}

    void process(ContextPtr ctx) override {
        // Capture a shared_ptr to options for the lambda
        auto options_capture = _options;

        if (options_capture->get_csp_nonce_enabled()) {
            std::string nonce = internal::generate_random_nonce();
            ctx->set("csp_nonce", nonce);
        }

        ctx->add_lifecycle_hook(
            [options_capture](Context<SessionType>& ctx_ref, HookPoint point) {
            if (point == HookPoint::PRE_RESPONSE_SEND) {
                const auto& opts = *options_capture; // Dereference shared_ptr to get options

                // Conditional HSTS: Only send over HTTPS
                if (opts.get_hsts_value()) {
                    std::string_view scheme_view = ctx_ref.request().uri().scheme();
                    if (scheme_view.compare("https") == 0) {
                        ctx_ref.response().set_header("Strict-Transport-Security", *opts.get_hsts_value());
                    }
                }
                if (opts.get_set_x_content_type_options_nosniff()) {
                    ctx_ref.response().set_header("X-Content-Type-Options", "nosniff");
                }
                if (opts.get_x_frame_options_value()) {
                    ctx_ref.response().set_header("X-Frame-Options", *opts.get_x_frame_options_value());
                }

                // CSP Logic with Nonce
                if (opts.get_csp_nonce_enabled()) {
                    std::optional<std::string> nonce_opt = ctx_ref.template get<std::string>("csp_nonce");
                    if (nonce_opt) {
                        const std::string& nonce = *nonce_opt;
                        if (!opts.get_content_security_policy_value().has_value()) {
                            // If user hasn't set a CSP, apply a default one with nonce
                            std::string default_csp_with_nonce = 
                                "default-src 'self'; "
                                "script-src 'self' 'nonce-" + nonce + "' 'strict-dynamic'; "
                                "style-src 'self' 'nonce-" + nonce + "'; "
                                "object-src 'none'; base-uri 'self'; form-action 'self';";
                            ctx_ref.response().set_header("Content-Security-Policy", default_csp_with_nonce);
                        } else {
                            // User has provided a CSP, set it. They are responsible for using the nonce.
                            ctx_ref.response().set_header("Content-Security-Policy", *opts.get_content_security_policy_value());
                        }
                    }
                } else if (opts.get_content_security_policy_value()) {
                    // Nonce not enabled, but user provided a CSP
                    ctx_ref.response().set_header("Content-Security-Policy", *opts.get_content_security_policy_value());
                }
                
                if (opts.get_csp_report_only_value()) {
                    ctx_ref.response().set_header("Content-Security-Policy-Report-Only", *opts.get_csp_report_only_value());
                }
                if (opts.get_referrer_policy_value()) {
                    ctx_ref.response().set_header("Referrer-Policy", *opts.get_referrer_policy_value());
                }
                if (opts.get_permissions_policy_value()) {
                    ctx_ref.response().set_header("Permissions-Policy", *opts.get_permissions_policy_value());
                }
                if (opts.get_coop_value()) {
                    ctx_ref.response().set_header("Cross-Origin-Opener-Policy", *opts.get_coop_value());
                }
                if (opts.get_coep_value()) {
                    ctx_ref.response().set_header("Cross-Origin-Embedder-Policy", *opts.get_coep_value());
                }
                if (opts.get_corp_value()) {
                    ctx_ref.response().set_header("Cross-Origin-Resource-Policy", *opts.get_corp_value());
                }
                if (opts.get_x_permitted_cross_domain_policies_value()) {
                    ctx_ref.response().set_header("X-Permitted-Cross-Domain-Policies", *opts.get_x_permitted_cross_domain_policies_value());
                }
            }
        });
        ctx->complete(AsyncTaskResult::CONTINUE);
    }

    std::string name() const override {
        return _name;
    }

    void cancel() override {
        // No-op
    }
    
    const SecurityHeadersOptions& get_options() const {
        return *_options;
    }

    void update_options(const SecurityHeadersOptions& new_options) {
        _options = std::make_shared<SecurityHeadersOptions>(new_options);
    }

private:
    std::shared_ptr<SecurityHeadersOptions> _options;
    std::string _name;
};

/**
 * @brief Factory function to create a SecurityHeadersMiddleware instance.
 * @tparam SessionType The session type.
 * @param options Configuration options for the security headers. Defaults to secure_defaults().
 * @param name Optional name for the middleware instance.
 * @return A shared pointer to the created SecurityHeadersMiddleware.
 */
template <typename SessionType>
std::shared_ptr<SecurityHeadersMiddleware<SessionType>>
security_headers_middleware(
    const SecurityHeadersOptions& options = SecurityHeadersOptions::secure_defaults(),
    const std::string& name = "SecurityHeadersMiddleware"
) {
    return std::make_shared<SecurityHeadersMiddleware<SessionType>>(options, name);
}

} // namespace qb::http 
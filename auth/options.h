#ifndef QBM_HTTP_AUTH_OPTIONS_H
#define QBM_HTTP_AUTH_OPTIONS_H

#include <chrono>
#include <string>
#include <vector>

namespace qb {
namespace http {
namespace auth {

/**
 * @brief Class for managing authentication configuration
 *
 * This class contains all options for configuring authentication,
 * including keys, algorithms, token validity durations, etc.
 */
class Options {
public:
    /**
     * @brief Supported authentication algorithms
     */
    enum class Algorithm {
        HMAC_SHA256,
        HMAC_SHA384,
        HMAC_SHA512,
        RSA_SHA256,
        RSA_SHA384,
        RSA_SHA512,
        ECDSA_SHA256,
        ECDSA_SHA384,
        ECDSA_SHA512,
        ED25519
    };

private:
    std::vector<unsigned char> _secret_key;
    std::string                _public_key;
    std::string                _private_key;
    Algorithm                  _algorithm = Algorithm::HMAC_SHA256;
    std::chrono::seconds       _token_expiration{3600}; // 1 hour default
    std::string                _token_issuer;
    std::string                _token_audience;
    std::string                _auth_header_name               = "Authorization";
    std::string                _auth_scheme                    = "Bearer";
    bool                       _require_signature_verification = true;
    bool                       _verify_expiration              = true;
    bool                       _verify_not_before              = true;
    bool                       _verify_issuer                  = false;
    bool                       _verify_audience                = false;
    std::chrono::seconds       _clock_skew_tolerance =
        std::chrono::seconds(0); // Default: no tolerance

public:
    Options() = default;

    /**
     * @brief Set the secret key for HMAC algorithms
     * @param secret Secret key
     * @return Reference to this Options object for chaining
     */
    Options &secret_key(const std::string &secret) {
        _secret_key.assign(secret.begin(), secret.end());
        return *this;
    }

    /**
     * @brief Set the secret key for HMAC algorithms
     * @param secret Secret key in bytes
     * @return Reference to this Options object for chaining
     */
    Options &secret_key(const std::vector<unsigned char> &secret) {
        _secret_key = secret;
        return *this;
    }

    /**
     * @brief Set the public key for asymmetric algorithms
     * @param key Public key in PEM format
     * @return Reference to this Options object for chaining
     */
    Options &public_key(const std::string &key) {
        _public_key = key;
        return *this;
    }

    /**
     * @brief Set the private key for asymmetric algorithms
     * @param key Private key in PEM format
     * @return Reference to this Options object for chaining
     */
    Options &private_key(const std::string &key) {
        _private_key = key;
        return *this;
    }

    /**
     * @brief Set the algorithm to use
     * @param alg Algorithm to use
     * @return Reference to this Options object for chaining
     */
    Options &algorithm(Algorithm alg) {
        _algorithm = alg;
        return *this;
    }

    /**
     * @brief Set token validity duration
     * @param seconds Duration in seconds
     * @return Reference to this Options object for chaining
     */
    Options &token_expiration(std::chrono::seconds seconds) {
        _token_expiration = seconds;
        return *this;
    }

    /**
     * @brief Set token issuer
     * @param issuer Issuer identifier
     * @return Reference to this Options object for chaining
     */
    Options &token_issuer(const std::string &issuer) {
        _token_issuer  = issuer;
        _verify_issuer = !issuer.empty();
        return *this;
    }

    /**
     * @brief Set token audience
     * @param audience Audience identifier
     * @return Reference to this Options object for chaining
     */
    Options &token_audience(const std::string &audience) {
        _token_audience  = audience;
        _verify_audience = !audience.empty();
        return *this;
    }

    /**
     * @brief Set authentication header name
     * @param name Header name
     * @return Reference to this Options object for chaining
     */
    Options &auth_header_name(const std::string &name) {
        _auth_header_name = name;
        return *this;
    }

    /**
     * @brief Set authentication scheme
     * @param scheme Scheme (e.g., "Bearer")
     * @return Reference to this Options object for chaining
     */
    Options &auth_scheme(const std::string &scheme) {
        _auth_scheme = scheme;
        return *this;
    }

    /**
     * @brief Enable/disable signature verification
     * @param verify true to enable, false to disable
     * @return Reference to this Options object for chaining
     */
    Options &require_signature_verification(bool verify) {
        _require_signature_verification = verify;
        return *this;
    }

    /**
     * @brief Enable/disable expiration verification
     * @param verify true to enable, false to disable
     * @return Reference to this Options object for chaining
     */
    Options &verify_expiration(bool verify) {
        _verify_expiration = verify;
        return *this;
    }

    /**
     * @brief Enable/disable not-before verification
     * @param verify true to enable, false to disable
     * @return Reference to this Options object for chaining
     */
    Options &verify_not_before(bool verify) {
        _verify_not_before = verify;
        return *this;
    }

    /**
     * @brief Set clock skew tolerance for time-based verifications
     * @param tolerance Tolerance in seconds
     * @return Reference to this Options object for chaining
     */
    Options &clock_skew_tolerance(std::chrono::seconds tolerance) {
        _clock_skew_tolerance = tolerance;
        return *this;
    }

    // Getters
    const std::vector<unsigned char> &get_secret_key() const {
        return _secret_key;
    }
    
    const std::string &get_public_key() const {
        return _public_key;
    }
    
    const std::string &get_private_key() const {
        return _private_key;
    }
    
    Algorithm get_algorithm() const {
        return _algorithm;
    }
    
    std::chrono::seconds get_token_expiration() const {
        return _token_expiration;
    }
    
    std::chrono::seconds get_clock_skew_tolerance() const {
        return _clock_skew_tolerance;
    }
    
    const std::string &get_token_issuer() const {
        return _token_issuer;
    }
    
    const std::string &get_token_audience() const {
        return _token_audience;
    }
    
    const std::string &get_auth_header_name() const {
        return _auth_header_name;
    }
    
    const std::string &get_auth_scheme() const {
        return _auth_scheme;
    }
    
    bool get_require_signature_verification() const {
        return _require_signature_verification;
    }
    
    bool get_verify_expiration() const {
        return _verify_expiration;
    }
    
    bool get_verify_not_before() const {
        return _verify_not_before;
    }
    
    bool get_verify_issuer() const {
        return _verify_issuer;
    }
    
    bool get_verify_audience() const {
        return _verify_audience;
    }
};

// Type alias for backward compatibility
using AuthOptions = Options;

} // namespace auth
} // namespace http
} // namespace qb

#endif // QBM_HTTP_AUTH_OPTIONS_H 